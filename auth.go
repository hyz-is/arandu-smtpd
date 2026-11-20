package smtpd

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"time"
)

// maxAuthSecret is the longest decoded AUTH response the server accepts.
const maxAuthSecret = 4096

// cmdAuth runs AUTH PLAIN and AUTH LOGIN. The credentials are checked by the
// Session; this code decides whether the client may try (TLS, the failure
// limit), decodes what it sends, and slows down a client that is guessing.
func (c *Conn) cmdAuth(arg []byte) (stop bool) {
	s := c.srv
	cfg := &s.cfg
	switch {
	case !cfg.authEnabled:
		c.refuse(errNotImplemented)
		return false
	case c.state == sNew:
		c.refuse(errNeedHello)
		return false
	case c.authed:
		c.refuse(errAlreadyAuthed)
		return false
	case c.state != sIdle:
		c.refuse(errAuthInProgress)
		return false
	case !c.tlsActive() && !cfg.allowInsecure:
		c.refuse(errAuthNeedsTLS)
		return false
	}
	ip := c.remote.Addr()
	if ip.IsValid() && s.guard.blocked(ip) {
		s.st.authBlocked.inc()
		c.log(slog.LevelInfo, "smtpd: AUTH refused, the client failed too often")
		c.refuse(errAuthBlocked)
		return false
	}

	word := arg
	var initial []byte
	if sp := bytes.IndexByte(arg, ' '); sp >= 0 {
		word, initial = arg[:sp], bytes.TrimLeft(arg[sp:], " ")
	}
	var mechanism string
	switch {
	case eqFold(word, "PLAIN"):
		mechanism = "PLAIN"
	case eqFold(word, "LOGIN"):
		mechanism = "LOGIN"
	default:
		c.refuse(errAuthMechanism)
		return false
	}

	if c.scratch == nil {
		c.scratch = make([]byte, 4096)
	}
	var user, pass string
	var e *Error
	if mechanism == "PLAIN" {
		user, pass, e, stop = c.authPlain(initial)
	} else {
		user, pass, e, stop = c.authLogin(initial)
	}
	if stop {
		return true
	}
	if e != nil {
		c.refuse(e)
		return false
	}

	err := c.session.Auth(mechanism, user, pass)
	if err == nil {
		s.st.authSuccess.inc()
		c.authed = true
		c.authUser = user
		c.authFails = 0
		c.log(slog.LevelInfo, "smtpd: authenticated", slog.String("mechanism", mechanism))
		c.send(errAuthOK)
		return false
	}

	reply := asError(err, ErrAuthFailed)
	if !reply.Temporary() {
		s.st.authFailure.inc()
		c.authFails++
		blocked := ip.IsValid() && s.guard.fail(ip)
		c.log(slog.LevelInfo, "smtpd: authentication failed",
			slog.String("mechanism", mechanism), slog.Bool("blocked", blocked))
		if !c.tarpit() {
			return true
		}
	}
	c.refuse(reply)
	return false
}

// tarpit waits before a failed AUTH is answered, longer for each failure on the
// connection, and reports false when the server began closing meanwhile.
func (c *Conn) tarpit() bool {
	cfg := &c.srv.cfg
	if cfg.authDelay <= 0 {
		return true
	}
	d := cfg.authDelay
	for i := 1; i < c.authFails && d < cfg.authDelayMax; i++ {
		d *= 2
	}
	d = min(d, cfg.authDelayMax)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.srv.done:
		return false
	}
}

// authLine reads one line of an AUTH exchange after sending prompt (the base64
// of the server's challenge, which may be empty) as a 334 reply. It returns the
// decoded bytes, in the connection's scratch buffer.
func (c *Conn) authLine(prompt string) (decoded []byte, e *Error, stop bool) {
	c.bw.Write(appendReply(c.rbuf[:0], 334, "", prompt))
	line, tooLong, err := c.readLine()
	if err != nil {
		c.readFailed(err)
		return nil, nil, true
	}
	if tooLong {
		return nil, errLineTooLong, false
	}
	return c.decodeAuth(line)
}

func (c *Conn) decodeAuth(line []byte) (decoded []byte, e *Error, stop bool) {
	if len(line) == 1 && line[0] == '*' {
		return nil, errAuthCancelled, false
	}
	if len(line) == 1 && line[0] == '=' {
		return c.scratch[:0], nil, false
	}
	if base64.StdEncoding.DecodedLen(len(line)) > len(c.scratch) || len(line) > maxAuthSecret*2 {
		return nil, errAuthSyntax, false
	}
	n, err := base64.StdEncoding.Decode(c.scratch, line)
	if err != nil {
		return nil, errAuthSyntax, false
	}
	return c.scratch[:n], nil, false
}

// authPlain reads PLAIN's single response: authzid NUL authcid NUL password.
// The authzid must be empty or equal to the authcid, because the server does
// not let a client act as somebody else.
func (c *Conn) authPlain(initial []byte) (user, pass string, e *Error, stop bool) {
	var resp []byte
	if len(initial) > 0 {
		resp, e, stop = c.decodeAuth(initial)
	} else {
		resp, e, stop = c.authLine("")
	}
	if e != nil || stop {
		return "", "", e, stop
	}
	defer clear(c.scratch)
	first := bytes.IndexByte(resp, 0)
	if first < 0 {
		return "", "", errAuthSyntax, false
	}
	second := bytes.IndexByte(resp[first+1:], 0)
	if second < 0 {
		return "", "", errAuthSyntax, false
	}
	second += first + 1
	authzid, authcid, password := resp[:first], resp[first+1:second], resp[second+1:]
	if len(authcid) == 0 || (len(authzid) > 0 && !bytes.Equal(authzid, authcid)) {
		return "", "", ErrAuthFailed, false
	}
	return string(authcid), string(password), nil, false
}

// authLogin reads LOGIN's two responses, the name and then the password, each
// asked for with the conventional base64 prompt. The name may come on the
// AUTH line itself.
func (c *Conn) authLogin(initial []byte) (user, pass string, e *Error, stop bool) {
	var resp []byte
	if len(initial) > 0 {
		resp, e, stop = c.decodeAuth(initial)
	} else {
		resp, e, stop = c.authLine("VXNlcm5hbWU6") // "Username:"
	}
	if e != nil || stop {
		return "", "", e, stop
	}
	user = string(resp)
	resp, e, stop = c.authLine("UGFzc3dvcmQ6") // "Password:"
	defer clear(c.scratch)
	if e != nil || stop {
		return "", "", e, stop
	}
	return user, string(resp), nil, false
}
