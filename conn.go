package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Where a connection is in the SMTP dialogue.
const (
	sNew  = iota // no HELO or EHLO yet
	sIdle        // greeted, no transaction
	sMail        // MAIL accepted, no recipient yet
	sRcpt        // at least one recipient accepted
)

var errShuttingDown = errors.New("smtpd: server is shutting down")

// Conn is one client connection. A Backend receives it in NewSession to learn
// who is calling; the accessors are safe to use from the Session's methods and
// from nowhere else, and the Conn is not valid once Session.Logout returns.
type Conn struct {
	srv       *Server
	id        uint64
	sessionID string

	raw     net.Conn // the socket: closed to end the connection, poked to wake a read
	plain   net.Conn // the socket after the PROXY header, before TLS
	nc      net.Conn // plain, or the TLS connection over it
	tlsConn *tls.Conn

	br *bufio.Reader
	bw *bufio.Writer

	remote     netip.AddrPort
	local      netip.AddrPort
	remoteAddr net.Addr
	localAddr  net.Addr
	ipHeld     bool

	session  Session
	state    int
	helo     string
	authed   bool
	authUser string
	errCount int
	rcpts    int
	utf8     bool

	mailOpts  MailOptions
	rcptOpts  RcptOptions
	notifyBuf [4]DSNNotify
	dot       dotReader
	bdat      *bdatState
	authFails int

	// Read deadlines. readTimeout applies to each read from the socket unless
	// absDeadline says the phase set one deadline for all of it.
	readTimeout  time.Duration
	absDeadline  bool
	canInterrupt bool
	idle         atomic.Bool

	scratch []byte
	rbuf    [512]byte
}

// bdatState is a message that arrives as BDAT chunks: Data runs in a goroutine
// that reads what the chunks write into the pipe.
type bdatState struct {
	pw       *io.PipeWriter
	done     chan error
	total    int64
	finished bool
	result   error
}

// ID is the connection's number, unique within the Server's lifetime.
func (c *Conn) ID() uint64 { return c.id }

// SessionID is a string that identifies the session in the logs, and that a
// Backend can store with the messages it accepts.
func (c *Conn) SessionID() string {
	if c.sessionID == "" {
		// Built on first use, because most connections never ask for it: it is
		// needed by the log when the log is on, and by a Backend that stores it.
		var b [40]byte
		id := append(b[:0], c.srv.idPrefix...)
		id = append(id, '-')
		id = strconv.AppendUint(id, c.id, 36)
		c.sessionID = string(id)
	}
	return c.sessionID
}

// RemoteAddr is the client's address: the one in the PROXY header when the
// server uses PROXY protocol, otherwise the socket's.
func (c *Conn) RemoteAddr() net.Addr {
	if c.remoteAddr == nil {
		if c.remote.IsValid() {
			c.remoteAddr = net.TCPAddrFromAddrPort(c.remote)
		} else {
			c.remoteAddr = c.raw.RemoteAddr()
		}
	}
	return c.remoteAddr
}

// RemoteAddrPort is RemoteAddr as a netip value, invalid when the transport is
// not TCP.
func (c *Conn) RemoteAddrPort() netip.AddrPort { return c.remote }

// LocalAddr is the address the client connected to.
func (c *Conn) LocalAddr() net.Addr {
	if c.localAddr == nil {
		if c.local.IsValid() {
			c.localAddr = net.TCPAddrFromAddrPort(c.local)
		} else {
			c.localAddr = c.raw.LocalAddr()
		}
	}
	return c.localAddr
}

// Hostname is the name the client gave in HELO or EHLO, empty before it did.
func (c *Conn) Hostname() string { return c.helo }

// TLS returns the state of the connection's TLS session, and false while the
// connection is not encrypted.
func (c *Conn) TLS() (tls.ConnectionState, bool) {
	if c.tlsConn == nil {
		return tls.ConnectionState{}, false
	}
	return c.tlsConn.ConnectionState(), true
}

// Username is the name the client authenticated as, empty before it did.
func (c *Conn) Username() string { return c.authUser }

// Server is the Server that accepted the connection.
func (c *Conn) Server() *Server { return c.srv }

func addrPortOf(a net.Addr) netip.AddrPort {
	switch a := a.(type) {
	case *net.TCPAddr:
		return a.AddrPort()
	case nil:
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// connReader is what the bufio.Reader reads. It is the one place a connection
// blocks, and so the one place that
//
//   - flushes the replies still buffered, which is how pipelined commands get
//     one packet of replies and a client that waits gets its reply;
//   - sets the read deadline;
//   - tells the server the connection is idle, so a shutdown can wake it.
type connReader struct{ c *Conn }

func (r connReader) Read(p []byte) (int, error) {
	c := r.c
	if c.bw.Buffered() > 0 {
		if err := c.bw.Flush(); err != nil {
			return 0, err
		}
	}
	if !c.absDeadline {
		c.nc.SetReadDeadline(time.Now().Add(c.readTimeout))
	}
	if c.canInterrupt {
		c.idle.Store(true)
		if c.srv.closing.Load() {
			c.idle.Store(false)
			return 0, errShuttingDown
		}
	}
	n, err := c.nc.Read(p)
	if c.canInterrupt {
		c.idle.Store(false)
	}
	return n, err
}

type connWriter struct{ c *Conn }

func (w connWriter) Write(p []byte) (int, error) {
	c := w.c
	c.nc.SetWriteDeadline(time.Now().Add(c.srv.cfg.writeTimeout))
	return c.nc.Write(p)
}

// appendReply appends one SMTP reply to b. A newline in msg starts a
// continuation line; carriage returns are dropped, so the text of a reply can
// never end the reply early or add one.
func appendReply(b []byte, code int, enh, msg string) []byte {
	if code < 100 || code > 999 {
		code = 451
	}
	for {
		line, rest, more := strings.Cut(msg, "\n")
		b = append(b, byte('0'+code/100), byte('0'+code/10%10), byte('0'+code%10))
		if more {
			b = append(b, '-')
		} else {
			b = append(b, ' ')
		}
		if enh != "" {
			b = append(b, enh...)
			b = append(b, ' ')
		}
		if strings.IndexByte(line, '\r') >= 0 {
			line = strings.ReplaceAll(line, "\r", "")
		}
		b = append(b, line...)
		b = append(b, '\r', '\n')
		if !more {
			return b
		}
		msg = rest
	}
}

func (c *Conn) send(e *Error) {
	c.bw.Write(appendReply(c.rbuf[:0], e.Code, e.Enhanced, e.Message))
}

// refuse sends a reply that counts as an error toward MaxErrors.
func (c *Conn) refuse(e *Error) {
	c.srv.st.protocolErrors.inc()
	c.errCount++
	c.send(e)
}

func (c *Conn) flush() error { return c.bw.Flush() }

func (c *Conn) log(level slog.Level, msg string, attrs ...slog.Attr) {
	l := c.srv.cfg.logger
	if !l.Enabled(context.Background(), level) {
		return
	}
	all := make([]slog.Attr, 0, len(attrs)+3)
	all = append(all, slog.Uint64("conn", c.id), slog.String("session", c.SessionID()), slog.String("remote", c.remote.String()))
	all = append(all, attrs...)
	l.LogAttrs(context.Background(), level, msg, all...)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// handle serves one accepted connection from start to finish.
func (s *Server) handle(nc net.Conn, implicit bool) {
	defer s.wg.Done()
	defer s.st.connsActive.add(-1)
	id := s.nextID.Add(1)
	c := &Conn{srv: s, id: id, raw: nc, plain: nc, nc: nc}
	c.remote = addrPortOf(nc.RemoteAddr())
	c.local = addrPortOf(nc.LocalAddr())
	s.register(c)
	defer s.unregister(c)
	defer nc.Close()
	defer func() {
		if r := recover(); r != nil {
			s.st.panics.inc()
			c.log(slog.LevelError, "smtpd: panic in a connection", slog.Any("panic", r))
		}
	}()
	c.run(implicit)
}

func (c *Conn) run(implicit bool) {
	s := c.srv
	cfg := &s.cfg

	if cfg.proxy && !c.readProxy() {
		return
	}
	if ip := c.remote.Addr(); ip.IsValid() {
		if !s.limiter.acquire(ip, cfg.maxConnsPerIP) {
			s.st.connsRefused.inc()
			c.log(slog.LevelInfo, "smtpd: too many connections from one client")
			s.refuse(c.plain, errTooManyConnsIP)
			return
		}
		if cfg.maxConnsPerIP > 0 {
			defer s.limiter.release(ip)
		}
	}

	if implicit && !c.handshake() {
		return
	}

	c.br = s.readers.Get().(*bufio.Reader)
	c.bw = s.writers.Get().(*bufio.Writer)
	c.br.Reset(connReader{c})
	c.bw.Reset(connWriter{c})
	defer func() {
		c.br.Reset(nil)
		c.bw.Reset(nil)
		s.readers.Put(c.br)
		s.writers.Put(c.bw)
	}()
	c.readTimeout = cfg.cmdTimeout

	if d := cfg.earlyTalker; d > 0 && !c.earlyTalkerCheck(d) {
		return
	}

	sess, err := s.Backend.NewSession(c)
	if err != nil {
		e := asError(err, errNoSession)
		c.log(slog.LevelInfo, "smtpd: the backend refused the connection", slog.String("reply", e.Error()))
		c.send(e)
		c.flush()
		return
	}
	s.st.sessions.inc()
	c.session = sess
	defer c.logout()

	c.log(slog.LevelInfo, "smtpd: connection open", slog.Bool("implicit_tls", implicit))
	c.bw.Write(cfg.greeting)

	c.canInterrupt = true
	c.loop()
	c.canInterrupt = false
	c.flush()
	c.log(slog.LevelInfo, "smtpd: connection closed")
}

func (c *Conn) logout() {
	c.abortBDAT()
	if c.state >= sMail {
		c.session.Reset()
	}
	if err := c.session.Logout(); err != nil {
		c.log(slog.LevelDebug, "smtpd: logout failed", slog.String("error", err.Error()))
	}
}

// readProxy reads the PROXY protocol header and replaces the client's address
// with the one it carries. It reports false when the connection must go.
func (c *Conn) readProxy() bool {
	s := c.srv
	if len(s.cfg.proxyTrusted) > 0 {
		trusted := false
		peer := c.remote.Addr().Unmap()
		for _, p := range s.cfg.proxyTrusted {
			if p.Contains(peer) {
				trusted = true
				break
			}
		}
		if !trusted {
			s.st.proxyFailures.inc()
			c.log(slog.LevelWarn, "smtpd: PROXY protocol from a peer that is not trusted")
			return false
		}
	}
	c.raw.SetReadDeadline(time.Now().Add(s.cfg.hsTimeout))
	br := bufio.NewReaderSize(c.raw, 512)
	h, err := readProxyHeader(br)
	c.raw.SetReadDeadline(time.Time{})
	if err != nil {
		s.st.proxyFailures.inc()
		c.log(slog.LevelWarn, "smtpd: bad PROXY protocol header", slog.String("error", err.Error()))
		return false
	}
	s.st.proxyHeaders.inc()
	if br.Buffered() > 0 {
		c.plain = &bufferedConn{Conn: c.raw, br: br}
		c.nc = c.plain
	}
	if !h.Local && h.Src.IsValid() {
		c.remote = h.Src
		c.local = h.Dst
		c.remoteAddr, c.localAddr = nil, nil
	}
	return true
}

// handshake runs the TLS handshake on the connection and reports whether it
// completed.
func (c *Conn) handshake() bool {
	s := c.srv
	tc := tls.Server(c.plain, s.cfg.tls)
	c.raw.SetDeadline(time.Now().Add(s.cfg.hsTimeout))
	err := tc.Handshake()
	c.raw.SetDeadline(time.Time{})
	if err != nil {
		s.st.tlsFailures.inc()
		c.log(slog.LevelInfo, "smtpd: TLS handshake failed", slog.String("error", err.Error()))
		return false
	}
	s.st.tlsHandshakes.inc()
	c.tlsConn = tc
	c.nc = tc
	return true
}

// earlyTalkerCheck waits d for the client to send something before the
// greeting. A client that does is rejected.
func (c *Conn) earlyTalkerCheck(d time.Duration) bool {
	c.readTimeout = d
	_, err := c.br.Peek(1)
	c.readTimeout = c.srv.cfg.cmdTimeout
	switch {
	case err == nil:
		c.srv.st.earlyTalkers.inc()
		c.log(slog.LevelInfo, "smtpd: the client spoke before the greeting")
		c.send(errEarlyTalker)
		c.flush()
		return false
	case isTimeout(err):
		return true
	}
	return false
}

// readLine reads one command line without its line ending. It reports a line
// that is too long (and has then consumed all of it), and the error that ended
// the connection.
func (c *Conn) readLine() (line []byte, tooLong bool, err error) {
	line, err = c.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		skipped := len(line)
		for err == bufio.ErrBufferFull {
			var more []byte
			more, err = c.br.ReadSlice('\n')
			if skipped += len(more); skipped > 1<<20 {
				return nil, false, errLineFlood
			}
		}
		if err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	line = line[:len(line)-1]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if len(line) > c.srv.cfg.maxLine {
		return nil, true, nil
	}
	return line, false, nil
}

var errLineFlood = errors.New("smtpd: a command line never ended")

// loop reads and answers commands until the connection ends.
func (c *Conn) loop() {
	cfg := &c.srv.cfg
	for {
		line, tooLong, err := c.readLine()
		if err != nil {
			c.readFailed(err)
			return
		}
		if tooLong {
			c.refuse(errLineTooLong)
			if c.tooManyErrors() {
				return
			}
			continue
		}
		c.srv.st.commands.inc()
		if hasControl(line) {
			c.refuse(errSyntax)
			if c.tooManyErrors() {
				return
			}
			continue
		}
		v, arg := splitCommand(line)
		if c.dispatch(v, arg) {
			return
		}
		if cfg.maxErrors > 0 && c.tooManyErrors() {
			return
		}
	}
}

func (c *Conn) tooManyErrors() bool {
	if m := c.srv.cfg.maxErrors; m > 0 && c.errCount >= m {
		c.send(errTooManyErrors)
		c.flush()
		c.log(slog.LevelInfo, "smtpd: too many errors, closing")
		return true
	}
	return false
}

// readFailed answers the error that ended a read of a command.
func (c *Conn) readFailed(err error) {
	switch {
	case errors.Is(err, errShuttingDown) || (isTimeout(err) && c.srv.closing.Load()):
		c.send(errShutdown)
	case isTimeout(err):
		c.srv.st.timeouts.inc()
		c.send(errIdleTimeout)
	default:
		c.log(slog.LevelDebug, "smtpd: read ended", slog.String("error", err.Error()))
	}
}

// dispatch runs one command. It reports whether the connection is to end.
func (c *Conn) dispatch(v verb, arg []byte) (stop bool) {
	switch v {
	case verbEHLO, verbHELO:
		c.cmdHello(v, arg)
	case verbMAIL:
		c.cmdMail(arg)
	case verbRCPT:
		c.cmdRcpt(arg)
	case verbDATA:
		return c.cmdData(arg)
	case verbBDAT:
		return c.cmdBDAT(arg)
	case verbRSET:
		c.endTx()
		c.send(errRSETOK)
	case verbNOOP:
		c.send(errNoopOK)
	case verbQUIT:
		c.send(errQuitOK)
		c.flush()
		return true
	case verbVRFY:
		c.send(errVRFY)
	case verbEXPN:
		c.refuse(errNotImplemented)
	case verbHELP:
		c.send(errHelpOK)
	case verbSTARTTLS:
		return c.cmdStartTLS(arg)
	case verbAUTH:
		return c.cmdAuth(arg)
	default:
		c.refuse(errSyntax)
	}
	return false
}

func (c *Conn) tlsActive() bool { return c.tlsConn != nil }

func (c *Conn) cmdHello(v verb, arg []byte) {
	if len(arg) == 0 || len(arg) > 255 {
		c.refuse(errSyntaxArgs)
		return
	}
	c.endTx()
	if string(arg) != c.helo {
		c.helo = string(arg)
	}
	c.state = sIdle
	if v == verbHELO {
		c.bw.Write(c.srv.cfg.heloReply)
		return
	}
	tlsIdx, authIdx := 0, 0
	if c.tlsActive() {
		tlsIdx = 1
	}
	if c.authed {
		authIdx = 1
	}
	c.bw.Write(c.srv.cfg.ehlo[tlsIdx][authIdx])
}

func (c *Conn) cmdMail(arg []byte) {
	cfg := &c.srv.cfg
	switch {
	case c.state == sNew:
		c.refuse(errNeedHello)
		return
	case c.state != sIdle:
		c.refuse(errNestedMail)
		return
	case cfg.requireTLS && !c.tlsActive():
		c.refuse(errTLSRequired)
		return
	case cfg.requireAuth && !c.authed:
		c.refuse(ErrAuthRequired)
		return
	}
	rest, ok := cutKeyword(arg, "FROM:")
	if !ok {
		c.refuse(errSyntaxArgs)
		return
	}
	addr, params, ok := parsePath(rest)
	if !ok {
		c.refuse(errSyntaxArgs)
		return
	}
	c.mailOpts = MailOptions{}
	if e := parseMailParams(params, &c.mailOpts, cfg.caps); e != nil {
		c.refuse(e)
		return
	}
	valid, nonASCII := checkAddress(addr, true)
	switch {
	case !valid:
		c.refuse(errBadAddress)
		return
	case nonASCII && !c.mailOpts.UTF8:
		c.refuse(errNeedUTF8)
		return
	case cfg.maxMessage > 0 && c.mailOpts.Size > cfg.maxMessage:
		c.refuse(errSizeExceeded)
		return
	}
	if err := c.session.Mail(string(addr), &c.mailOpts); err != nil {
		c.backendRefused("MAIL", err, errBackendFailed)
		return
	}
	c.state = sMail
	c.rcpts = 0
	c.utf8 = c.mailOpts.UTF8
	c.send(errMailOK)
}

// backendRefused answers the error a Session method returned. An *Error is sent
// as it is; any other error is logged and answered with fallback, so what the
// application failed on never reaches the client.
func (c *Conn) backendRefused(what string, err error, fallback *Error) {
	e := asError(err, fallback)
	if e == fallback {
		if _, isErr := err.(*Error); !isErr {
			c.log(slog.LevelWarn, "smtpd: the session failed a command", slog.String("command", what), slog.String("error", err.Error()))
		}
	}
	c.refuse(e)
}

func (c *Conn) cmdRcpt(arg []byte) {
	cfg := &c.srv.cfg
	switch c.state {
	case sNew:
		c.refuse(errNeedHello)
		return
	case sIdle:
		c.refuse(errNeedMail)
		return
	}
	if cfg.maxRcpts > 0 && c.rcpts >= cfg.maxRcpts {
		c.send(errTooManyRcpt)
		return
	}
	rest, ok := cutKeyword(arg, "TO:")
	if !ok {
		c.refuse(errSyntaxArgs)
		return
	}
	addr, params, ok := parsePath(rest)
	if !ok {
		c.refuse(errSyntaxArgs)
		return
	}
	c.rcptOpts = RcptOptions{Notify: c.notifyBuf[:0]}
	if e := parseRcptParams(params, &c.rcptOpts, cfg.caps); e != nil {
		c.refuse(e)
		return
	}
	valid, nonASCII := checkAddress(addr, false)
	switch {
	case !valid:
		c.refuse(errBadAddress)
		return
	case nonASCII && !c.utf8:
		c.refuse(errNeedUTF8)
		return
	}
	if err := c.session.Rcpt(string(addr), &c.rcptOpts); err != nil {
		c.srv.st.rcptRefused.inc()
		c.backendRefused("RCPT", err, errBackendFailed)
		return
	}
	c.srv.st.rcptAccepted.inc()
	c.rcpts++
	c.state = sRcpt
	c.send(errRcptOK)
}

// endTx ends the transaction in progress, if any, and tells the Session.
func (c *Conn) endTx() {
	c.abortBDAT()
	if c.state >= sMail {
		c.session.Reset()
		c.state = sIdle
	}
	c.rcpts = 0
}

func (c *Conn) cmdData(arg []byte) (stop bool) {
	cfg := &c.srv.cfg
	switch {
	case len(arg) != 0:
		c.refuse(errSyntaxArgs)
		return false
	case c.bdat != nil:
		c.refuse(errDataAfterBDAT)
		return false
	case c.state == sNew:
		c.refuse(errNeedHello)
		return false
	case c.state == sIdle:
		c.refuse(errBadSequence)
		return false
	case c.state == sMail:
		c.refuse(errNeedRcpt)
		return false
	}
	c.send(errDataGo)
	if err := c.flush(); err != nil {
		return true
	}

	// The whole message has one deadline, and the connection cannot be woken
	// by a shutdown meanwhile: a message in progress is allowed to finish.
	c.nc.SetReadDeadline(time.Now().Add(cfg.dataTimeout))
	c.absDeadline = true
	c.canInterrupt = false
	c.dot.reset(c.br, cfg.maxMessage, cfg.rejectBareLF)
	err := c.session.Data(&c.dot)
	if c.scratch == nil {
		c.scratch = make([]byte, 4096)
	}
	drainErr := c.dot.drain(c.scratch[:4096], cfg.drainLimit)
	c.absDeadline = false
	c.canInterrupt = true
	if drainErr != nil {
		c.srv.st.messagesRefused.inc()
		if errors.Is(drainErr, errDrainLimit) {
			c.send(errSizeExceeded)
			c.flush()
		} else if isTimeout(drainErr) {
			c.srv.st.timeouts.inc()
			c.send(errIdleTimeout)
			c.flush()
		}
		c.log(slog.LevelInfo, "smtpd: the message did not arrive", slog.String("error", drainErr.Error()))
		return true
	}
	c.srv.st.dataBytes.add(c.dot.n)

	switch {
	case c.dot.tooLarge:
		c.srv.st.messagesRefused.inc()
		c.send(errSizeExceeded)
	case cfg.rejectBareLF && c.dot.bareLF:
		c.srv.st.messagesRefused.inc()
		c.send(errBareLF)
	case err != nil:
		c.srv.st.messagesRefused.inc()
		c.backendRefused("DATA", err, errBackendFailed)
	default:
		c.srv.st.messages.inc()
		c.send(errDataOK)
	}
	c.endTx()
	return false
}

// parseBDAT reads "<size> [LAST]".
func parseBDAT(arg []byte) (size int64, last, ok bool) {
	sp := bytes.IndexByte(arg, ' ')
	num := arg
	if sp >= 0 {
		num = arg[:sp]
		rest := bytes.TrimLeft(arg[sp:], " ")
		if !eqFold(rest, "LAST") {
			return 0, false, false
		}
		last = true
	}
	size, ok = parseUint(num)
	return size, last, ok
}

func (c *Conn) cmdBDAT(arg []byte) (stop bool) {
	cfg := &c.srv.cfg
	if !cfg.chunking {
		c.refuse(errChunkingOff)
		return false
	}
	size, last, ok := parseBDAT(arg)
	if !ok {
		// Without a size there is nothing to skip, and the chunk that follows
		// would be read as commands. The client is broken, so it goes.
		c.refuse(errBadChunk)
		c.flush()
		return true
	}

	var fail *Error
	switch {
	case c.state == sNew:
		fail = errNeedHello
	case c.state == sIdle:
		fail = errBadSequence
	case c.state == sMail:
		fail = errNeedRcpt
	case cfg.maxMessage > 0 && (c.bdat != nil && c.bdat.total+size > cfg.maxMessage || size > cfg.maxMessage):
		fail = errSizeExceeded
	}
	if fail != nil {
		if size > cfg.drainLimit {
			c.refuse(fail)
			c.flush()
			return true
		}
		if err := c.discard(size); err != nil {
			return true
		}
		c.srv.st.messagesRefused.inc()
		c.refuse(fail)
		if c.state >= sMail {
			c.endTx()
		}
		return false
	}

	if c.bdat == nil {
		c.startBDAT()
	}
	b := c.bdat
	c.nc.SetReadDeadline(time.Now().Add(cfg.dataTimeout))
	c.absDeadline = true
	c.canInterrupt = false
	sink := !b.finished
	for remaining := size; remaining > 0; {
		if c.br.Buffered() == 0 {
			if _, err := c.br.Peek(1); err != nil {
				c.absDeadline = false
				c.abortBDAT()
				return true
			}
		}
		chunk, _ := c.br.Peek(int(min(int64(c.br.Buffered()), remaining)))
		if sink {
			if _, err := b.pw.Write(chunk); err != nil {
				sink = false
			}
		}
		c.br.Discard(len(chunk))
		remaining -= int64(len(chunk))
	}
	c.absDeadline = false
	c.canInterrupt = true
	b.total += size

	if !sink && !b.finished {
		// The Backend stopped reading before the end: its answer is already
		// decided, and it is the answer to this chunk.
		b.result = <-b.done
		b.finished = true
	}
	if !last {
		if b.finished && b.result != nil {
			c.srv.st.messagesRefused.inc()
			c.backendRefused("BDAT", b.result, errBackendFailed)
			c.endTx()
			return false
		}
		c.send(&Error{250, "2.0.0", strconv.FormatInt(size, 10) + " octets received"})
		return false
	}

	if !b.finished {
		b.pw.Close()
		b.result = <-b.done
		b.finished = true
	}
	c.srv.st.dataBytes.add(b.total)
	if err := b.result; err != nil {
		c.srv.st.messagesRefused.inc()
		c.backendRefused("DATA", err, errBackendFailed)
	} else {
		c.srv.st.messages.inc()
		c.send(errDataOK)
	}
	c.endTx()
	return false
}

// discard reads and throws away n bytes of a chunk.
func (c *Conn) discard(n int64) error {
	c.nc.SetReadDeadline(time.Now().Add(c.srv.cfg.dataTimeout))
	c.absDeadline = true
	c.canInterrupt = false
	defer func() { c.absDeadline = false; c.canInterrupt = true }()
	_, err := io.CopyN(io.Discard, c.br, n)
	return err
}

// startBDAT starts the goroutine that runs Session.Data over the chunks.
func (c *Conn) startBDAT() {
	pr, pw := io.Pipe()
	b := &bdatState{pw: pw, done: make(chan error, 1)}
	c.bdat = b
	sess := c.session
	st := &c.srv.st
	go func() {
		var err error
		defer func() {
			if r := recover(); r != nil {
				st.panics.inc()
				err = fmt.Errorf("smtpd: panic in Session.Data: %v", r)
			}
			// Whatever the Backend did with the pipe, nothing writes to it
			// any more once Data has returned.
			pr.CloseWithError(io.ErrClosedPipe)
			b.done <- err
		}()
		err = sess.Data(pr)
	}()
}

// abortBDAT stops a message that arrives as chunks, and waits for the
// Session's Data to return, so that the Session is not used from two
// goroutines.
func (c *Conn) abortBDAT() {
	b := c.bdat
	if b == nil {
		return
	}
	c.bdat = nil
	if !b.finished {
		b.pw.CloseWithError(io.ErrUnexpectedEOF)
		<-b.done
	}
}

func (c *Conn) cmdStartTLS(arg []byte) (stop bool) {
	s := c.srv
	switch {
	case len(arg) != 0:
		c.refuse(errSyntaxArgs)
		return false
	case c.tlsActive():
		c.refuse(errAlreadyTLS)
		return false
	case s.cfg.tls == nil:
		c.refuse(errNoTLS)
		return false
	}
	// Whatever the client sent after STARTTLS before the handshake would be
	// read as plaintext after it: the injection RFC 3207 section 6 warns about.
	if c.br.Buffered() > 0 {
		c.send(errPipelinedTLS)
		c.flush()
		return true
	}
	c.send(errStartTLSGo)
	if err := c.flush(); err != nil {
		return true
	}
	c.endTx()

	tc := tls.Server(c.plain, s.cfg.tls)
	c.raw.SetDeadline(time.Now().Add(s.cfg.hsTimeout))
	err := tc.Handshake()
	c.raw.SetDeadline(time.Time{})
	if err != nil {
		s.st.tlsFailures.inc()
		c.log(slog.LevelInfo, "smtpd: STARTTLS handshake failed", slog.String("error", err.Error()))
		return true
	}
	s.st.tlsHandshakes.inc()
	c.tlsConn = tc
	c.nc = tc
	c.br.Reset(connReader{c})
	c.bw.Reset(connWriter{c})
	// RFC 3207: the server forgets what it learned before the handshake.
	c.state = sNew
	c.helo = ""
	c.authed = false
	c.authUser = ""
	return false
}
