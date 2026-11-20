package smtpd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerClosed is returned by Serve, ServeTLS, ListenAndServe and
// ListenAndServeTLS after Shutdown or Close.
var ErrServerClosed = errors.New("smtpd: server closed")

// Server is an SMTP server. Fill in the fields, then call Serve (or
// ServeTLS) once for each listener: a Server can serve many listeners at once,
// with and without implicit TLS, and they share its limits and its counters.
//
// The fields are read when the first listener starts and must not change after
// that. In every numeric field, 0 means the default and a negative number means
// no limit (or, for a duration, off), so the zero Server is a safe one.
//
// A Server never relays and never accepts a recipient by itself: every
// decision is the Session's. Run it behind a Backend that says yes only to what
// the application wants, and it answers everything else.
type Server struct {
	// Backend creates the Session of each connection. It is required.
	Backend Backend

	// Hostname is the name in the greeting and in the EHLO reply. The default
	// is the host's own name.
	Hostname string
	// Banner is the text after "ESMTP" in the greeting. The default is
	// "ready".
	Banner string

	// TLSConfig enables STARTTLS on listeners served with Serve and is the
	// configuration of listeners served with ServeTLS. The server clones it,
	// and raises MinVersion to TLS 1.2 if it is lower. Set GetCertificate (for
	// instance from a CertReloader) to renew the certificate without a restart.
	TLSConfig *tls.Config

	// AllowInsecureAuth lets a client authenticate on a connection that is not
	// encrypted. It is off: AUTH is offered and accepted only after TLS.
	AllowInsecureAuth bool
	// DisableAuth removes AUTH from the server, which is right for a server that
	// only receives mail (an MX).
	DisableAuth bool
	// RequireAuth refuses MAIL on a connection that has not authenticated, with
	// 530 5.7.0. A Session can still refuse more; it cannot accept less than
	// this.
	RequireAuth bool
	// RequireTLS refuses MAIL on a connection that is not encrypted, with 530
	// 5.7.0, so a client has to STARTTLS (or use the implicit-TLS port) first.
	RequireTLS bool

	// MaxMessageBytes is the largest message accepted. The default is 10 MiB.
	MaxMessageBytes int64
	// MaxRecipients is the most recipients in one transaction. The default is
	// 100.
	MaxRecipients int
	// MaxConnections is the most connections open at once, across every
	// listener. The default is 10000.
	MaxConnections int
	// MaxConnectionsPerIP is the most connections one client may hold: an IPv4
	// address, or an IPv6 /64. The default is 100. Behind a load balancer it
	// counts the address the PROXY header gives.
	MaxConnectionsPerIP int
	// MaxErrors is how many refused commands a connection may collect before
	// the server hangs up on it with 421. Unknown commands, commands out of
	// order, bad syntax and recipients the Session refuses all count. The
	// default is 10.
	MaxErrors int
	// MaxLineLength is the longest command line, in bytes, line ending
	// excluded. The default is 4096, which holds an AUTH PLAIN with a long
	// secret.
	MaxLineLength int
	// ReadBufferSize and WriteBufferSize are the sizes of the buffers each
	// connection borrows from a pool. The defaults are 8192 and 4096.
	ReadBufferSize  int
	WriteBufferSize int

	// CommandTimeout is how long the server waits for the next command, 5
	// minutes by default. DataTimeout is how long a whole message may take to
	// arrive, 10 minutes by default. WriteTimeout is how long it waits for the
	// client to take a reply, 1 minute by default. HandshakeTimeout bounds a
	// TLS handshake and the PROXY header, 30 seconds by default.
	CommandTimeout   time.Duration
	DataTimeout      time.Duration
	WriteTimeout     time.Duration
	HandshakeTimeout time.Duration

	// EarlyTalkerDelay, when positive, makes the server wait that long before
	// the greeting and hang up on a client that sends something in the
	// meantime: legitimate clients wait for the greeting, and spam software
	// often does not. It delays every connection by that long, so it is off by
	// default.
	EarlyTalkerDelay time.Duration

	// MaxAuthFailures is how many failed AUTH attempts one client may make
	// within AuthFailureWindow before it is blocked for AuthBlockDuration. While
	// it is blocked, AUTH answers 454 without asking the Session. The defaults
	// are 10, 10 minutes and 15 minutes.
	MaxAuthFailures   int
	AuthFailureWindow time.Duration
	AuthBlockDuration time.Duration
	// AuthFailureDelay is the pause before the reply to a failed AUTH, and it
	// doubles with each failure on the same connection up to
	// AuthFailureDelayMax. The defaults are 1 second and 10 seconds.
	AuthFailureDelay    time.Duration
	AuthFailureDelayMax time.Duration

	// ProxyProtocol makes every connection start with a PROXY protocol header,
	// version 1 or 2, as a load balancer sends, and uses the address in it as
	// the client's. A connection that does not start with one is dropped, so it
	// is only for listeners that nothing but the balancer can reach.
	ProxyProtocol bool
	// ProxyTrusted limits whose PROXY header is believed to these networks. A
	// connection from anywhere else is dropped. Empty trusts every peer.
	ProxyTrusted []netip.Prefix

	// RejectBareLF refuses a message that has a line feed not preceded by a
	// carriage return, with 550 5.6.0. The end of the message is never taken
	// from a bare line feed either way.
	RejectBareLF bool

	// DisablePipelining, DisableChunking, DisableSMTPUTF8 and DisableDSN
	// remove an extension from the EHLO reply. PIPELINING only advertises what
	// the server always handles, so disabling it changes the reply and nothing
	// else.
	DisablePipelining bool
	DisableChunking   bool
	DisableSMTPUTF8   bool
	DisableDSN        bool

	// Logger receives the server's log records, with conn and session
	// attributes. The default discards them.
	Logger *slog.Logger

	// Now is the clock the auth limiter reads. It is for tests.
	Now func() time.Time

	initOnce sync.Once
	initErr  error
	cfg      settings
	st       stats

	nextID    atomic.Uint64
	idPrefix  string
	closing   atomic.Bool
	done      chan struct{}
	doneOnce  sync.Once
	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     [shardCount]connShard
	wg        sync.WaitGroup
	limiter   *ipLimiter
	guard     *authGuard
	readers   sync.Pool
	writers   sync.Pool
}

type connShard struct {
	mu sync.Mutex
	m  map[*Conn]struct{}
	_  [40]byte
}

// settings is the Server's configuration with its defaults applied, so the
// connections read plain fields.
type settings struct {
	hostname      string
	banner        string
	tls           *tls.Config
	maxMessage    int64
	maxRcpts      int
	maxConns      int64
	maxConnsPerIP int
	maxErrors     int
	maxLine       int
	readBuf       int
	writeBuf      int
	cmdTimeout    time.Duration
	dataTimeout   time.Duration
	writeTimeout  time.Duration
	hsTimeout     time.Duration
	earlyTalker   time.Duration
	authDelay     time.Duration
	authDelayMax  time.Duration
	drainLimit    int64
	allowInsecure bool
	authEnabled   bool
	requireAuth   bool
	proxy         bool
	proxyTrusted  []netip.Prefix
	rejectBareLF  bool
	chunking      bool
	caps          caps
	logger        *slog.Logger
	ehlo          [2][2][]byte // [tls active][authenticated]
	startTLSOffer bool
	pipelining    bool
	requireTLS    bool
	greeting      []byte
	heloReply     []byte
}

func orDefault[T ~int | ~int64](v, def T) T {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

var (
	errNoBackend   = errors.New("smtpd: Server.Backend is nil")
	errNoTLSConfig = errors.New("smtpd: TLSConfig is nil or has no certificate")
)

func (s *Server) init() error {
	s.initOnce.Do(func() { s.initErr = s.prepare() })
	return s.initErr
}

func (s *Server) prepare() error {
	if s.Backend == nil {
		return errNoBackend
	}
	c := &s.cfg
	c.hostname = s.Hostname
	if c.hostname == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			c.hostname = h
		} else {
			c.hostname = "localhost"
		}
	}
	c.banner = s.Banner
	if c.banner == "" {
		c.banner = "ready"
	}
	if s.TLSConfig != nil {
		if len(s.TLSConfig.Certificates) == 0 && s.TLSConfig.GetCertificate == nil && s.TLSConfig.GetConfigForClient == nil {
			return errNoTLSConfig
		}
		c.tls = s.TLSConfig.Clone()
		if c.tls.MinVersion < tls.VersionTLS12 {
			c.tls.MinVersion = tls.VersionTLS12
		}
	}
	c.maxMessage = orDefault(s.MaxMessageBytes, 10<<20)
	c.maxRcpts = orDefault(s.MaxRecipients, 100)
	c.maxConns = int64(orDefault(s.MaxConnections, 10000))
	c.maxConnsPerIP = orDefault(s.MaxConnectionsPerIP, 100)
	c.maxErrors = orDefault(s.MaxErrors, 10)
	c.maxLine = orDefault(s.MaxLineLength, 4096)
	if c.maxLine == 0 {
		// A negative setting means "as long as is reasonable", not unbounded:
		// the line is read into a buffer.
		c.maxLine = 64 << 10
	}
	if c.maxLine < 512 {
		c.maxLine = 512
	}
	c.readBuf = orDefault(s.ReadBufferSize, 8192)
	if c.readBuf < c.maxLine+2 {
		c.readBuf = c.maxLine + 2
	}
	c.writeBuf = orDefault(s.WriteBufferSize, 4096)
	if c.writeBuf < 512 {
		c.writeBuf = 512
	}
	c.cmdTimeout = orDefault(s.CommandTimeout, 5*time.Minute)
	c.dataTimeout = orDefault(s.DataTimeout, 10*time.Minute)
	c.writeTimeout = orDefault(s.WriteTimeout, time.Minute)
	c.hsTimeout = orDefault(s.HandshakeTimeout, 30*time.Second)
	c.earlyTalker = max(s.EarlyTalkerDelay, 0)
	c.authDelay = orDefault(s.AuthFailureDelay, time.Second)
	c.authDelayMax = orDefault(s.AuthFailureDelayMax, 10*time.Second)
	if c.authDelayMax < c.authDelay {
		c.authDelayMax = c.authDelay
	}
	c.drainLimit = 64 << 20
	c.allowInsecure = s.AllowInsecureAuth
	c.authEnabled = !s.DisableAuth
	c.requireAuth = s.RequireAuth
	c.proxy = s.ProxyProtocol
	c.proxyTrusted = append([]netip.Prefix(nil), s.ProxyTrusted...)
	c.rejectBareLF = s.RejectBareLF
	c.chunking = !s.DisableChunking
	c.pipelining = !s.DisablePipelining
	c.caps = caps{smtputf8: !s.DisableSMTPUTF8, dsn: !s.DisableDSN}
	c.startTLSOffer = c.tls != nil
	c.logger = s.Logger
	if c.logger == nil {
		c.logger = slog.New(slog.DiscardHandler)
	}
	c.requireTLS = s.RequireTLS
	c.greeting = appendReply(nil, 220, "", c.hostname+" ESMTP "+c.banner)
	c.heloReply = appendReply(nil, 250, "", c.hostname)
	c.buildEHLO()

	now := s.Now
	if now == nil {
		now = time.Now
	}
	s.limiter = newIPLimiter()
	s.guard = newAuthGuard(orDefault(s.MaxAuthFailures, 10),
		orDefault(s.AuthFailureWindow, 10*time.Minute),
		orDefault(s.AuthBlockDuration, 15*time.Minute), now)
	for i := range s.conns {
		s.conns[i].m = make(map[*Conn]struct{})
	}
	s.listeners = make(map[net.Listener]struct{})
	s.done = make(chan struct{})
	s.readers.New = func() any { return bufio.NewReaderSize(nil, c.readBuf) }
	s.writers.New = func() any { return bufio.NewWriterSize(nil, c.writeBuf) }

	var pfx [4]byte
	if _, err := rand.Read(pfx[:]); err != nil {
		return err
	}
	s.idPrefix = hex.EncodeToString(pfx[:])
	return nil
}

// buildEHLO precomputes the four EHLO replies, so answering EHLO writes bytes
// that already exist.
func (c *settings) buildEHLO() {
	for tlsActive := 0; tlsActive < 2; tlsActive++ {
		for authed := 0; authed < 2; authed++ {
			var lines []string
			if c.pipelining {
				lines = append(lines, "PIPELINING")
			}
			if c.maxMessage > 0 {
				lines = append(lines, "SIZE "+itoa(c.maxMessage))
			} else {
				lines = append(lines, "SIZE")
			}
			if tlsActive == 0 && c.startTLSOffer {
				lines = append(lines, "STARTTLS")
			}
			lines = append(lines, "ENHANCEDSTATUSCODES", "8BITMIME")
			if c.caps.dsn {
				lines = append(lines, "DSN")
			}
			if c.caps.smtputf8 {
				lines = append(lines, "SMTPUTF8")
			}
			if c.chunking {
				lines = append(lines, "CHUNKING")
			}
			if c.authEnabled && authed == 0 && (tlsActive == 1 || c.allowInsecure) {
				lines = append(lines, "AUTH PLAIN LOGIN")
			}
			var b []byte
			b = append(b, "250-"...)
			b = append(b, c.hostname...)
			b = append(b, "\r\n"...)
			for i, l := range lines {
				if i == len(lines)-1 {
					b = append(b, "250 "...)
				} else {
					b = append(b, "250-"...)
				}
				b = append(b, l...)
				b = append(b, "\r\n"...)
			}
			c.ehlo[tlsActive][authed] = b
		}
	}
}

// ListenAndServe listens on the TCP address addr and serves SMTP with STARTTLS
// (when TLSConfig is set) on it, until Shutdown or Close.
func (s *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// ListenAndServeTLS listens on the TCP address addr and serves SMTP inside TLS
// from the first byte (the submission-over-TLS port, 465), until Shutdown or
// Close. TLSConfig is required.
func (s *Server) ListenAndServeTLS(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.ServeTLS(l)
}

// Serve accepts connections on l and serves SMTP on each, with STARTTLS offered
// when TLSConfig is set. It returns when l fails or the server is closed, and
// it closes l.
func (s *Server) Serve(l net.Listener) error { return s.serve(l, false) }

// ServeTLS is Serve for a listener whose connections are TLS from the first
// byte. TLSConfig is required. It does not offer STARTTLS, since the connection
// is already encrypted.
func (s *Server) ServeTLS(l net.Listener) error { return s.serve(l, true) }

func (s *Server) serve(l net.Listener, implicit bool) error {
	if err := s.init(); err != nil {
		l.Close()
		return err
	}
	if implicit && s.cfg.tls == nil {
		l.Close()
		return errNoTLSConfig
	}

	s.mu.Lock()
	if s.closing.Load() {
		s.mu.Unlock()
		l.Close()
		return ErrServerClosed
	}
	s.listeners[l] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
		l.Close()
		s.wg.Done()
	}()

	var backoff time.Duration
	for {
		nc, err := l.Accept()
		if err != nil {
			if s.closing.Load() {
				return ErrServerClosed
			}
			var te interface{ Temporary() bool }
			if errors.As(err, &te) && te.Temporary() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff *= 2; backoff > time.Second {
					backoff = time.Second
				}
				s.cfg.logger.LogAttrs(context.Background(), slog.LevelWarn, "smtpd: accept failed, retrying",
					slog.String("error", err.Error()), slog.Duration("retry_in", backoff))
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		s.accept(nc, implicit)
	}
}

func (s *Server) accept(nc net.Conn, implicit bool) {
	s.st.connsAccepted.inc()
	n := s.st.connsActive.v.Add(1)
	if s.cfg.maxConns > 0 && n > s.cfg.maxConns {
		s.st.connsActive.add(-1)
		s.st.connsRefused.inc()
		s.refuse(nc, errTooManyConns)
		return
	}
	s.wg.Add(1)
	go s.handle(nc, implicit)
}

// refuse answers a connection with a 421 and closes it. The reply is a single
// short write to an empty socket buffer, so it does not hold up the caller.
func (s *Server) refuse(nc net.Conn, e *Error) {
	nc.SetWriteDeadline(time.Now().Add(time.Second))
	var b [128]byte
	nc.Write(appendReply(b[:0], e.Code, e.Enhanced, e.Message))
	nc.Close()
}

func (s *Server) register(c *Conn) {
	sh := &s.conns[c.id%shardCount]
	sh.mu.Lock()
	sh.m[c] = struct{}{}
	sh.mu.Unlock()
}

func (s *Server) unregister(c *Conn) {
	sh := &s.conns[c.id%shardCount]
	sh.mu.Lock()
	delete(sh.m, c)
	sh.mu.Unlock()
}

// Shutdown stops accepting connections and lets the ones in progress finish: a
// connection waiting for a command is told 421 and closed at once, and one in
// the middle of a message gets to finish it. When ctx ends first, the
// remaining connections are closed and ctx's error is returned.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.init(); err != nil {
		return err
	}
	s.mu.Lock()
	s.closing.Store(true)
	s.doneOnce.Do(func() { close(s.done) })
	for l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()
	s.interruptIdle()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			s.Close()
			<-done
			return ctx.Err()
		case <-tick.C:
			// A connection that went idle after the first sweep, between two
			// messages, is caught by the next one.
			s.interruptIdle()
		}
	}
}

// Close stops the listeners and closes every connection at once.
func (s *Server) Close() error {
	if err := s.init(); err != nil {
		return err
	}
	s.mu.Lock()
	s.closing.Store(true)
	s.doneOnce.Do(func() { close(s.done) })
	for l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()
	for i := range s.conns {
		sh := &s.conns[i]
		sh.mu.Lock()
		for c := range sh.m {
			c.raw.Close()
		}
		sh.mu.Unlock()
	}
	return nil
}

// interruptIdle wakes every connection that is blocked waiting for a command,
// so it notices the server is closing.
func (s *Server) interruptIdle() {
	now := time.Now()
	for i := range s.conns {
		sh := &s.conns[i]
		sh.mu.Lock()
		for c := range sh.m {
			if c.idle.Load() {
				c.raw.SetReadDeadline(now)
			}
		}
		sh.mu.Unlock()
	}
}

// UnblockAuth forgets the failed AUTH attempts of a client and lifts its block,
// for an operator who knows the client is who it says it is. addr is the
// address the server sees: the one in the PROXY header when there is one. An
// IPv6 address stands for its whole /64.
func (s *Server) UnblockAuth(addr netip.Addr) {
	if s.init() != nil {
		return
	}
	s.guard.unblock(addr)
}
