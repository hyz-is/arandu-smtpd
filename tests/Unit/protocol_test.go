package unit_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

func TestTheServerRefusesToStartWithoutABackend(t *testing.T) {
	l := listen(t)
	srv := &smtpd.Server{}
	if err := srv.Serve(l); err == nil {
		t.Fatal("Serve accepted a Server with no Backend")
	}
}

func TestServeTLSNeedsATLSConfig(t *testing.T) {
	l := listen(t)
	srv := newServer(&backend{})
	if err := srv.ServeTLS(l); err == nil {
		t.Fatal("ServeTLS ran without a TLSConfig")
	}
}

func TestAServerWithATLSConfigThatHasNoCertificateRefusesToStart(t *testing.T) {
	l := listen(t)
	srv := newServer(&backend{})
	srv.TLSConfig = &tls.Config{}
	if err := srv.Serve(l); err == nil {
		t.Fatal("Serve accepted a TLSConfig with no certificate")
	}
}

func TestStandardLibraryClientDeliversAMessage(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)

	body := "Subject: hi\r\n\r\nline one\r\n.starts with a dot\r\n..two dots\r\nlast line\r\n"
	err := smtp.SendMail(addr, nil, "alice@example.com", []string{"bob@example.org", "carol@example.org"}, []byte(body))
	if err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	msgs := b.all()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.From != "alice@example.com" {
		t.Errorf("From = %q", m.From)
	}
	if got := strings.Join(m.Rcpts, ","); got != "bob@example.org,carol@example.org" {
		t.Errorf("Rcpts = %q", got)
	}
	if string(m.Data) != body {
		t.Errorf("Data = %q, want %q", m.Data, body)
	}
	if m.TLS {
		t.Error("the message arrived over TLS on a server that has none")
	}
}

func TestStandardLibraryClientAuthenticatesAfterSTARTTLS(t *testing.T) {
	b := &backend{users: map[string]string{"api": "secret-key"}}
	addr := start(t, tlsServer(t, b), false)

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH was offered before TLS")
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS was not offered")
	}
	if err := c.StartTLS(clientTLS()); err != nil {
		t.Fatal(err)
	}
	if ok, params := c.Extension("AUTH"); !ok || !strings.Contains(params, "PLAIN") || !strings.Contains(params, "LOGIN") {
		t.Fatalf("AUTH after TLS = %v %q", ok, params)
	}
	if err := c.Auth(smtp.PlainAuth("", "api", "secret-key", "127.0.0.1")); err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if err := c.Mail("a@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("b@example.org"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: x\r\n\r\nbody\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}

	m := b.all()[0]
	if m.User != "api" || !m.TLS || m.Hostname != "client.test" {
		t.Errorf("user=%q tls=%v hostname=%q", m.User, m.TLS, m.Hostname)
	}
	if _, logouts := b.counts(); logouts != 1 {
		waitFor(t, "Logout", func() bool { _, l := b.counts(); return l == 1 })
	}
}

func TestPlainAuthWithTheWrongPasswordIsRefused(t *testing.T) {
	b := &backend{users: map[string]string{"api": "secret-key"}}
	addr := start(t, tlsServer(t, b), false)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.StartTLS(clientTLS()); err != nil {
		t.Fatal(err)
	}
	err = c.Auth(smtp.PlainAuth("", "api", "wrong", "127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "535") || !strings.Contains(err.Error(), "5.7.8") {
		t.Fatalf("Auth = %v, want a 535 5.7.8", err)
	}
}

func TestAuthIsRefusedBeforeTLSEvenIfAClientTriesIt(t *testing.T) {
	b := &backend{users: map[string]string{"u": "p"}}
	addr := start(t, tlsServer(t, b), false)
	r := dial(t, addr)
	r.hello()
	plain := base64.StdEncoding.EncodeToString([]byte("\x00u\x00p"))
	r.expect("AUTH PLAIN "+plain, "538 5.7.11")
	if b.authCalls != 0 {
		t.Fatal("the Session was asked to check a credential sent in clear text")
	}
}

func TestAllowInsecureAuthOffersAndAcceptsAuthInTheClear(t *testing.T) {
	b := &backend{users: map[string]string{"u": "p"}}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	lines := r.hello()
	if !hasPrefixLine(lines, "AUTH PLAIN LOGIN") {
		t.Fatalf("AUTH not offered: %v", lines)
	}
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")), "235 2.7.0")
	// A second EHLO after authenticating no longer offers AUTH.
	lines = r.expect("EHLO again", "250 ")
	if hasPrefixLine(lines, "AUTH") {
		t.Fatal("AUTH offered again after the client authenticated")
	}
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")), "503 5.5.1")
}

func TestAuthPlainWithoutAnInitialResponseAndLoginPrompts(t *testing.T) {
	b := &backend{users: map[string]string{"api": "k-123"}}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	addr := start(t, srv, false)

	r := dial(t, addr)
	r.hello()
	r.expect("AUTH PLAIN", "334 ")
	r.expect(base64.StdEncoding.EncodeToString([]byte("\x00api\x00k-123")), "235 ")

	r2 := dial(t, addr)
	r2.hello()
	got := r2.expect("AUTH LOGIN", "334 VXNlcm5hbWU6")
	_ = got
	r2.expect(base64.StdEncoding.EncodeToString([]byte("api")), "334 UGFzc3dvcmQ6")
	r2.expect(base64.StdEncoding.EncodeToString([]byte("k-123")), "235 ")

	r3 := dial(t, addr)
	r3.hello()
	r3.expect("AUTH LOGIN "+base64.StdEncoding.EncodeToString([]byte("api")), "334 UGFzc3dvcmQ6")
	r3.expect(base64.StdEncoding.EncodeToString([]byte("nope")), "535 ")
}

func TestAuthRefusesBadEncodingAndCancellation(t *testing.T) {
	b := &backend{users: map[string]string{"u": "p"}}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("AUTH PLAIN !!!not-base64!!!", "501 5.5.2")
	r.expect("AUTH PLAIN", "334 ")
	r.expect("*", "501 5.0.0")
	r.expect("AUTH CRAM-MD5", "504 ")
	// PLAIN with an authzid that is somebody else.
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("admin\x00u\x00p")), "535 ")
	// Missing NULs.
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("nonuls")), "501 5.5.2")
	if b.authCalls != 0 {
		t.Fatalf("Auth was called %d times for malformed responses", b.authCalls)
	}
	r.expect("NOOP", "250 ")
}

func TestImplicitTLSListener(t *testing.T) {
	b := &backend{users: map[string]string{"api": "key"}}
	addr := start(t, tlsServer(t, b), true)

	c, err := tls.Dial("tcp", addr, clientTLS())
	if err != nil {
		t.Fatal(err)
	}
	cl, err := smtp.NewClient(c, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if ok, _ := cl.Extension("STARTTLS"); ok {
		t.Error("STARTTLS offered inside TLS")
	}
	if ok, _ := cl.Extension("AUTH"); !ok {
		t.Error("AUTH not offered inside TLS")
	}
	if err := cl.Auth(smtp.PlainAuth("", "api", "key", "localhost")); err != nil {
		t.Fatal(err)
	}
	if err := cl.Mail("a@x.test"); err != nil {
		t.Fatal(err)
	}
	if err := cl.Rcpt("b@x.test"); err != nil {
		t.Fatal(err)
	}
	w, _ := cl.Data()
	io.WriteString(w, "Subject: tls\r\n\r\nhello\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if m := b.all()[0]; !m.TLS || m.User != "api" {
		t.Fatalf("tls=%v user=%q", m.TLS, m.User)
	}
}

func TestSTARTTLSAfterCommandsPipelinedBehindItIsRefusedAndClosed(t *testing.T) {
	addr := start(t, tlsServer(t, &backend{}), false)
	r := dial(t, addr)
	r.hello()
	// The injected command arrives in the same packet as STARTTLS.
	r.write("STARTTLS\r\nMAIL FROM:<evil@x.test>\r\n")
	if l := r.line(); !strings.HasPrefix(l, "554 5.5.1") {
		t.Fatalf("got %q, want a 554 5.5.1", l)
	}
	r.closed()
}

func TestSTARTTLSResetsWhatTheClientLearned(t *testing.T) {
	b := &backend{users: map[string]string{"u": "p"}}
	addr := start(t, tlsServer(t, b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("STARTTLS", "220 2.0.0")
	tc := tls.Client(r.conn, clientTLS())
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	r2 := &raw{t: t, conn: tc, br: bufio.NewReader(tc)}
	// The state before the handshake is forgotten: HELO is required again.
	r2.expect("MAIL FROM:<a@x.test>", "503 5.5.1")
	lines := r2.expect("EHLO again", "250 ")
	if hasLine(lines, "STARTTLS") {
		t.Error("STARTTLS offered again")
	}
	r2.expect("STARTTLS", "503 ")
}

func TestPipeliningAnswersEveryCommandInOrder(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.expect("", "220 ")
	r.write("EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nRCPT TO:<c@x.test>\r\nDATA\r\n")
	want := []string{"250 ", "250 2.1.0", "250 2.1.5", "250 2.1.5", "354 "}
	for i, w := range want {
		lines := r.reply()
		if last := lines[len(lines)-1]; !strings.HasPrefix(last, w) {
			t.Fatalf("reply %d = %q, want %q", i, last, w)
		}
	}
	// The body, the end of data, the next transaction and QUIT in one write.
	r.write("Subject: p\r\n\r\nbody\r\n.\r\nMAIL FROM:<d@x.test>\r\nRSET\r\nQUIT\r\n")
	for _, w := range []string{"250 2.0.0", "250 2.1.0", "250 2.0.0", "221 "} {
		if l := r.line(); !strings.HasPrefix(l, w) {
			t.Fatalf("got %q, want %q", l, w)
		}
	}
	r.closed()
	if n := len(b.all()); n != 1 {
		t.Fatalf("%d messages", n)
	}
}

func TestEHLOAdvertisesTheExtensions(t *testing.T) {
	srv := tlsServer(t, &backend{})
	srv.MaxMessageBytes = 5 << 20
	addr := start(t, srv, false)
	r := dial(t, addr)
	lines := r.hello()
	for _, want := range []string{"PIPELINING", "SIZE 5242880", "STARTTLS", "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8", "CHUNKING"} {
		if !hasLine(lines, want) {
			t.Errorf("EHLO does not offer %s: %v", want, lines)
		}
	}
	if hasPrefixLine(lines, "AUTH") {
		t.Error("AUTH offered in the clear")
	}
	if !strings.HasPrefix(lines[0], "250-mx.test") {
		t.Errorf("first line = %q", lines[0])
	}
}

func TestExtensionsCanBeDisabled(t *testing.T) {
	srv := newServer(&backend{})
	srv.DisablePipelining, srv.DisableChunking, srv.DisableSMTPUTF8, srv.DisableDSN = true, true, true, true
	srv.MaxMessageBytes = -1
	addr := start(t, srv, false)
	r := dial(t, addr)
	lines := r.hello()
	for _, not := range []string{"PIPELINING", "CHUNKING", "SMTPUTF8", "DSN"} {
		if hasLine(lines, not) {
			t.Errorf("%s is still offered", not)
		}
	}
	if !hasLine(lines, "SIZE") {
		t.Errorf("SIZE with no limit should be offered bare: %v", lines)
	}
	r.expect("MAIL FROM:<a@x.test> SMTPUTF8", "555 5.5.4")
	r.expect("MAIL FROM:<a@x.test> RET=FULL", "555 5.5.4")
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test> NOTIFY=NEVER", "555 5.5.4")
	r.send("BDAT 5 LAST")
	r.expect("", "502 5.5.1")
}

func TestHELOWorksToo(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.expect("", "220 mx.test ESMTP")
	r.expect("HELO old.client", "250 mx.test")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestCommandsOutOfOrder(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.expect("", "220 ")
	r.expect("MAIL FROM:<a@x.test>", "503 5.5.1")
	r.expect("RCPT TO:<b@x.test>", "503 5.5.1")
	r.expect("DATA", "503 5.5.1")
	r.expect("EHLO c.test", "250 ")
	r.expect("RCPT TO:<b@x.test>", "503 5.5.1")
	r.expect("DATA", "503 5.5.1")
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("MAIL FROM:<a@x.test>", "503 5.5.1")
	r.expect("DATA", "554 5.5.1")
	r.expect("RSET", "250 ")
	r.expect("RCPT TO:<b@x.test>", "503 5.5.1")
}

func TestSyntaxErrors(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxErrors = -1
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	for cmd, want := range map[string]string{
		"FOO":                                   "500 5.5.1",
		"":                                      "500 5.5.1",
		"MAIL":                                  "501 5.5.4",
		"MAIL FROM":                             "501 5.5.4",
		"MAIL FROM:<a@b":                        "501 5.5.4",
		"MAIL FROM:<a@b>junk":                   "501 5.5.4",
		"MAIL FROM:<a b@c.test>":                "501 5.1.7",
		"MAIL FROM:<@c.test>":                   "501 5.5.4",
		"MAIL FROM:<a@>":                        "501 5.1.7",
		"MAIL FROM:<a@c..test>":                 "501 5.1.7",
		"MAIL FROM:<a@c.test> SIZE=abc":         "501 5.5.4",
		"MAIL FROM:<a@c.test> SIZE=1 SIZE=2":    "501 5.5.4",
		"MAIL FROM:<a@c.test> BODY=BINARYMIME":  "555 5.5.4",
		"MAIL FROM:<a@c.test> NOPE=1":           "555 5.5.4",
		"MAIL FROM:<a@c.test> ENVID=bad space":  "555 5.5.4",
		"MAIL FROM:<a@c.test> ENVID=bad=eq":     "501 5.5.4",
		"MAIL FROM:<a@c.test> RET=SOME":         "501 5.5.4",
		"MAIL FROM:<héllo@c.test>":              "553 5.6.7",
		"HELO":                                  "501 5.5.4",
		"EHLO":                                  "501 5.5.4",
		"DATA now":                              "501 5.5.4",
		"STARTTLS now":                          "501 5.5.4",
		"EXPN list":                             "502 5.5.1",
		"MAIL FROM:<ok@c.test> ENVID=a+2Bb+3Dc": "250 2.1.0",
	} {
		r.send(cmd)
		lines := r.reply()
		if got := lines[len(lines)-1]; !strings.HasPrefix(got, want) {
			t.Errorf("%q: got %q, want %q", cmd, got, want)
		}
		if strings.HasPrefix(want, "250") {
			r.expect("RSET", "250 ")
		}
	}
}

func TestSessionIsStillUsableAfterManyRefusedCommandsUnderTheLimit(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxErrors = -1
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	for i := 0; i < 50; i++ {
		r.expect("BOGUS", "500 ")
	}
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestTooManyErrorsHangsUp(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxErrors = 3
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("BOGUS", "500 ")
	r.expect("BOGUS", "500 ")
	r.send("BOGUS")
	lines := r.reply()
	if !strings.HasPrefix(lines[0], "500 ") {
		t.Fatalf("got %q", lines)
	}
	if l := r.line(); !strings.HasPrefix(l, "421 4.7.0") {
		t.Fatalf("got %q, want a 421 4.7.0", l)
	}
	r.closed()
}

func TestRecipientsAreAnsweredOneByOne(t *testing.T) {
	b := &backend{rcptErr: map[string]error{
		"nobody@x.test": smtpd.ErrMailboxUnavailable,
		"later@x.test":  &smtpd.Error{Code: 451, Enhanced: "4.2.1", Message: "mailbox busy"},
		"broken@x.test": fmt.Errorf("database exploded: password=hunter2"),
	}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<ok1@x.test>", "250 2.1.5")
	r.expect("RCPT TO:<nobody@x.test>", "550 5.1.1")
	r.expect("RCPT TO:<later@x.test>", "451 4.2.1 mailbox busy")
	lines := r.expect("RCPT TO:<broken@x.test>", "451 4.3.0")
	if strings.Contains(strings.Join(lines, " "), "hunter2") {
		t.Fatal("the text of an internal error reached the client")
	}
	r.expect("RCPT TO:<ok2@x.test>", "250 2.1.5")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nb\r\n.\r\n")
	r.expect("", "250 ")
	m := b.all()[0]
	if got := strings.Join(m.Rcpts, ","); got != "ok1@x.test,ok2@x.test" {
		t.Fatalf("recipients = %q", got)
	}
}

func TestDataWithNoAcceptedRecipientIsRefused(t *testing.T) {
	b := &backend{rcptErr: map[string]error{"nobody@x.test": smtpd.ErrMailboxUnavailable}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<nobody@x.test>", "550 ")
	r.expect("DATA", "554 5.5.1")
}

func TestMaxRecipients(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxRecipients = 3
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	for i := 0; i < 3; i++ {
		r.expect(fmt.Sprintf("RCPT TO:<r%d@x.test>", i), "250 ")
	}
	r.expect("RCPT TO:<r4@x.test>", "452 4.5.3")
	// The transaction goes on with what was accepted.
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nb\r\n.\r\n")
	r.expect("", "250 ")
}

func TestMailRefusedByTheSession(t *testing.T) {
	b := &backend{mailErr: &smtpd.Error{Code: 550, Enhanced: "5.7.1", Message: "sender blocked"}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "550 5.7.1 sender blocked")
	r.expect("RCPT TO:<b@x.test>", "503 ")
}

func TestMultilineReplyFromTheSession(t *testing.T) {
	b := &backend{mailErr: &smtpd.Error{Code: 550, Enhanced: "5.7.1", Message: "line one\nline two\r\nline three"}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.send("MAIL FROM:<a@x.test>")
	lines := r.reply()
	want := []string{"550-5.7.1 line one", "550-5.7.1 line two", "550 5.7.1 line three"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", lines, want)
	}
}

func TestDefaultSessionRefusesEverything(t *testing.T) {
	srv := newServer(smtpd.RefuseBackend{})
	srv.AllowInsecureAuth = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")), "535 ")
	r.expect("MAIL FROM:<a@x.test>", "554 5.7.1")
}

type embeddedRefuse struct {
	smtpd.RefuseSession
	from string
}

func (s *embeddedRefuse) Mail(from string, _ *smtpd.MailOptions) error { s.from = from; return nil }

func TestEmbeddingRefuseSessionNeverRelays(t *testing.T) {
	srv := newServer(smtpd.BackendFunc(func(*smtpd.Conn) (smtpd.Session, error) { return &embeddedRefuse{}, nil }))
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@elsewhere.test>", "554 5.7.1")
	r.expect("DATA", "554 5.5.1")
}

func TestRequireAuthAndRequireTLS(t *testing.T) {
	b := &backend{users: map[string]string{"u": "p"}}
	srv := tlsServer(t, b)
	srv.RequireAuth = true
	srv.RequireTLS = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "530 5.7.0 Must issue a STARTTLS")
	r.expect("STARTTLS", "220 ")
	tc := tls.Client(r.conn, clientTLS())
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	r2 := &raw{t: t, conn: tc, br: bufio.NewReader(tc)}
	r2.expect("EHLO c.test", "250 ")
	r2.expect("MAIL FROM:<a@x.test>", "530 5.7.0 Authentication required")
	r2.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")), "235 ")
	r2.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestDSNAndUTF8ParametersReachTheBackend(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<hélio@exemplo.test> SMTPUTF8 SIZE=1234 BODY=8BITMIME RET=HDRS ENVID=QQ314159+2Bx AUTH=<>", "250 ")
	r.expect("RCPT TO:<jülia@exemplo.test> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;j+C3+BClia@exemplo.test", "250 ")
	r.expect("RCPT TO:<b@x.test> NOTIFY=NEVER", "250 ")
	r.expect("RCPT TO:<c@x.test> ORCPT=utf-8;j\\x{FC}lia@x.test", "250 ")
	r.expect("RCPT TO:<d@x.test> NOTIFY=NEVER,DELAY", "501 5.5.4")
	r.expect("RCPT TO:<d@x.test> NOTIFY=SUCCESS,SUCCESS", "501 5.5.4")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nb\r\n.\r\n")
	r.expect("", "250 ")

	m := b.all()[0]
	o := m.MailOpts
	if o.Size != 1234 || o.Body != smtpd.Body8BitMIME || !o.UTF8 || o.Return != smtpd.ReturnHeaders || o.EnvelopeID != "QQ314159+x" || o.Auth != "" {
		t.Errorf("MailOptions = %+v", o)
	}
	if m.From != "hélio@exemplo.test" {
		t.Errorf("From = %q", m.From)
	}
	r0 := m.RcptOpts[0]
	if len(r0.Notify) != 3 || r0.Notify[0] != smtpd.NotifySuccess || r0.Notify[1] != smtpd.NotifyFailure || r0.Notify[2] != smtpd.NotifyDelay {
		t.Errorf("Notify = %v", r0.Notify)
	}
	if r0.OriginalRecipientType != "rfc822" || r0.OriginalRecipient != "jülia@exemplo.test" {
		t.Errorf("ORCPT = %q %q", r0.OriginalRecipientType, r0.OriginalRecipient)
	}
	if n := m.RcptOpts[1].Notify; len(n) != 1 || n[0] != smtpd.NotifyNever {
		t.Errorf("Notify = %v", n)
	}
	if r2 := m.RcptOpts[2]; r2.OriginalRecipientType != "utf-8" || r2.OriginalRecipient != "jülia@x.test" {
		t.Errorf("ORCPT = %q %q", r2.OriginalRecipientType, r2.OriginalRecipient)
	}
}

func TestNonASCIIAddressNeedsSMTPUTF8(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<jülia@x.test>", "553 5.6.7")
}

func TestNullSenderAndPostmaster(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<>", "250 ")
	r.expect("RCPT TO:<Postmaster>", "250 ")
	r.expect("RCPT TO:<@relay.test:user@x.test>", "250 ")
	r.expect("RCPT TO:<\"quoted local\"@x.test>", "250 ")
	r.expect("RCPT TO:<>", "501 5.1.7")
	r.expect("DATA", "354 ")
	r.write("Subject: dsn\r\n\r\nb\r\n.\r\n")
	r.expect("", "250 ")
	m := b.all()[0]
	if m.From != "" || strings.Join(m.Rcpts, ",") != `Postmaster,user@x.test,"quoted local"@x.test` {
		t.Fatalf("from=%q rcpts=%q", m.From, m.Rcpts)
	}
}

func TestMailWithoutAngleBracketsAndWithSpaceAfterTheColon(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.expect("mail from: a@x.test", "250 ")
	r.expect("rcpt to:b@x.test", "250 ")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nb\r\n.\r\n")
	r.expect("", "250 ")
}

func TestMessageSizeLimit(t *testing.T) {
	b := &backend{}
	srv := newServer(b)
	srv.MaxMessageBytes = 1000
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()

	// Declared above the limit: refused before any data is sent.
	r.expect("MAIL FROM:<a@x.test> SIZE=5000", "552 5.3.4")

	// Not declared, and over the limit: the whole message is read and refused,
	// and the connection is still in step afterwards.
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write(strings.Repeat("x", 100) + "\r\n")
	for i := 0; i < 30; i++ {
		r.write(strings.Repeat("y", 998) + "\r\n")
	}
	r.write(".\r\n")
	r.expect("", "552 5.3.4")
	r.expect("NOOP", "250 ")

	// Exactly at the limit is accepted.
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write(strings.Repeat("a", 998) + "\r\n") // 1000 bytes with the CRLF
	r.write(".\r\n")
	r.expect("", "250 ")
	if got := len(b.all()); got != 1 || len(b.all()[0].Data) != 1000 {
		t.Fatalf("messages = %d", got)
	}

	// One byte over is refused.
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write(strings.Repeat("a", 999) + "\r\n")
	r.write(".\r\n")
	r.expect("", "552 ")
}

func TestTheReaderGivenToDataReportsTooLarge(t *testing.T) {
	var gotErr error
	b := &backend{dataHook: func(r io.Reader) error {
		_, err := io.Copy(io.Discard, r)
		gotErr = err
		return err
	}}
	srv := newServer(b)
	srv.MaxMessageBytes = 100
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write(strings.Repeat("a", 500) + "\r\n.\r\n")
	r.expect("", "552 5.3.4")
	if gotErr != smtpd.ErrDataTooLarge {
		t.Fatalf("Data saw %v, want ErrDataTooLarge", gotErr)
	}
}

func TestADataErrorFromTheSessionIsAnswered(t *testing.T) {
	b := &backend{dataErr: &smtpd.Error{Code: 554, Enhanced: "5.7.1", Message: "spam"}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nb\r\n.\r\n")
	r.expect("", "554 5.7.1 spam")
	// The transaction is over, and a new one works.
	r.expect("RCPT TO:<b@x.test>", "503 ")
	b.dataErr = nil
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestADataSessionThatReadsNothingStillLeavesTheConnectionInStep(t *testing.T) {
	b := &backend{dataHook: func(io.Reader) error { return nil }}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write("line\r\n.. dotted\r\n.\r\n")
	r.expect("", "250 ")
	r.expect("NOOP", "250 ")
}

func TestDotStuffingAndTheEndOfData(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write("first\r\n..\r\n...three\r\n.\r\n")
	r.expect("", "250 ")
	if got := string(b.all()[0].Data); got != "first\r\n.\r\n..three\r\n" {
		t.Fatalf("Data = %q", got)
	}
}

func TestBareLFDoesNotEndTheMessage(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	// Smuggling attempt: a "message end" written with bare line feeds, then a
	// command that a server which honoured it would run.
	r.write("Subject: s\r\n\r\nbody\n.\nMAIL FROM:<evil@x.test>\r\n")
	r.write("still the message\r\n.\r\n")
	r.expect("", "250 ")
	got := string(b.all()[0].Data)
	if !strings.Contains(got, "MAIL FROM:<evil@x.test>") || !strings.Contains(got, "body\n.\nMAIL") {
		// A bare LF is not a line end, so the dot after it is data too.
		t.Fatalf("Data = %q", got)
	}
	if n := len(b.all()); n != 1 {
		t.Fatalf("%d messages: the bare LF ended a message", n)
	}
}

func TestRejectBareLF(t *testing.T) {
	b := &backend{}
	srv := newServer(b)
	srv.RejectBareLF = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nbare\nlf\r\n.\r\n")
	r.expect("", "550 5.6.0")
	r.expect("NOOP", "250 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nproper")
	if n := len(b.all()); n != 1 {
		t.Fatalf("%d messages", n)
	}
}

func TestLongCommandLineIsRefusedAndTheConnectionContinues(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxLineLength = 600
	srv.MaxErrors = -1
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("NOOP "+strings.Repeat("x", 599), "500 5.5.2")
	r.expect("NOOP "+strings.Repeat("x", 5000), "500 5.5.2")
	r.expect("NOOP "+strings.Repeat("x", 100000), "500 5.5.2")
	r.expect("NOOP", "250 ")
}

func TestControlCharactersInACommandAreRefused(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.write("NOOP\rMAIL FROM:<a@x.test>\r\n")
	r.expect("", "500 5.5.1")
	r.write("NOOP\x00\r\n")
	r.expect("", "500 5.5.1")
	r.expect("NOOP", "250 ")
}

func TestCommandsWithBareLFAreAccepted(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.expect("", "220 ")
	r.write("NOOP\nQUIT\n")
	r.expect("", "250 ")
	r.expect("", "221 ")
}

func TestVRFYAndHELPDoNotLeak(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.expect("VRFY someone", "252 2.5.2")
	r.expect("HELP", "214 ")
	r.expect("QUIT", "221 ")
	r.closed()
}

func TestBDATChunks(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	lines := r.hello()
	if !hasLine(lines, "CHUNKING") {
		t.Fatal("CHUNKING not offered")
	}
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")

	part1 := "Subject: chunked\r\n\r\nfirst part\r\n"
	part2 := ".not stuffed\r\n.\r\nsecond part, no trailing CRLF"
	r.write(fmt.Sprintf("BDAT %d\r\n%s", len(part1), part1))
	r.expect("", "250 2.0.0 "+fmt.Sprint(len(part1))+" octets received")
	r.write(fmt.Sprintf("BDAT %d LAST\r\n%s", len(part2), part2))
	r.expect("", "250 2.0.0")
	if got := string(b.all()[0].Data); got != part1+part2 {
		t.Fatalf("Data = %q", got)
	}
	// And the connection takes another transaction, with DATA this time.
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestBDATPipelinedInOnePacketWithTheTransaction(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.expect("", "220 ")
	body := "Subject: s\r\n\r\nhello"
	r.write("EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\n" +
		fmt.Sprintf("BDAT 10\r\n%sBDAT %d LAST\r\n%s", body[:10], len(body)-10, body[10:]) +
		"QUIT\r\n")
	for _, w := range []string{"250 ", "250 2.1.0", "250 2.1.5", "250 2.0.0 10 octets", "250 2.0.0", "221 "} {
		lines := r.reply()
		if !strings.HasPrefix(lines[len(lines)-1], w) {
			t.Fatalf("got %q, want %q", lines, w)
		}
	}
	if string(b.all()[0].Data) != body {
		t.Fatalf("Data = %q", b.all()[0].Data)
	}
}

func TestBDATZeroLast(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.write("BDAT 5\r\nhello")
	r.expect("", "250 ")
	r.expect("BDAT 0 LAST", "250 2.0.0")
	if string(b.all()[0].Data) != "hello" {
		t.Fatalf("Data = %q", b.all()[0].Data)
	}
}

func TestBDATSequenceErrorsConsumeTheirChunk(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	// No transaction: the chunk is read and the command refused, and what
	// follows is a command again, not data.
	r.write("BDAT 13 LAST\r\nNOOP\r\nXXXXXXXNOOP\r\n")
	r.expect("", "503 5.5.1")
	r.expect("", "250 ")
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.write("BDAT 4 LAST\r\nabcd")
	r.expect("", "554 5.5.1")
	r.expect("NOOP", "250 ")
}

func TestBDATBadSyntaxHangsUp(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("BDAT abc", "501 5.5.4")
	r.closed()
}

func TestBDATOverTheLimitIsRefusedAndDiscarded(t *testing.T) {
	b := &backend{}
	srv := newServer(b)
	srv.MaxMessageBytes = 100
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.write("BDAT 60\r\n" + strings.Repeat("a", 60))
	r.expect("", "250 ")
	r.write("BDAT 60 LAST\r\n" + strings.Repeat("b", 60))
	r.expect("", "552 5.3.4")
	r.expect("NOOP", "250 ")
	if len(b.all()) != 0 {
		t.Fatal("a message over the limit was delivered")
	}
	// A new transaction is clean.
	r.transaction("a@x.test", "b@x.test", "Subject: ok\r\n\r\nb")
	if len(b.all()) != 1 {
		t.Fatal("no message after the refused one")
	}
}

func TestBDATWhenTheSessionStopsReadingEarly(t *testing.T) {
	b := &backend{dataHook: func(r io.Reader) error {
		buf := make([]byte, 4)
		io.ReadFull(r, buf)
		return &smtpd.Error{Code: 554, Enhanced: "5.7.1", Message: "enough"}
	}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.write("BDAT 100\r\n" + strings.Repeat("a", 100))
	r.expect("", "554 5.7.1 enough")
	// The transaction is over: a further chunk is refused and consumed.
	r.write("BDAT 3 LAST\r\nabc")
	r.expect("", "503 ")
	r.expect("NOOP", "250 ")
}

func TestDATAAfterBDATIsRefused(t *testing.T) {
	addr := start(t, newServer(&backend{}), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.write("BDAT 3\r\nabc")
	r.expect("", "250 ")
	r.expect("DATA", "503 5.5.1")
	r.expect("RSET", "250 ")
}

func TestRSETDuringBDATReleasesTheBackend(t *testing.T) {
	released := make(chan error, 1)
	b := &backend{dataHook: func(r io.Reader) error {
		_, err := io.Copy(io.Discard, r)
		released <- err
		return err
	}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.write("BDAT 3\r\nabc")
	r.expect("", "250 ")
	r.expect("RSET", "250 ")
	select {
	case err := <-released:
		if err == nil {
			t.Fatal("Data was released without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Data is still waiting after RSET")
	}
}

func TestResetIsCalledWhenATransactionEnds(t *testing.T) {
	b := &backend{}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if resets, _ := b.counts(); resets != 1 {
		t.Fatalf("resets after a message = %d, want 1", resets)
	}
	r.expect("RSET", "250 ")
	if resets, _ := b.counts(); resets != 1 {
		t.Fatalf("RSET with no transaction called Reset (%d)", resets)
	}
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RSET", "250 ")
	if resets, _ := b.counts(); resets != 2 {
		t.Fatalf("resets = %d, want 2", resets)
	}
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.conn.Close()
	waitFor(t, "Logout", func() bool { _, l := b.counts(); return l == 1 })
	if resets, _ := b.counts(); resets != 3 {
		t.Fatalf("an abandoned transaction did not reset (%d)", resets)
	}
}

func TestTheBackendCanRefuseAConnection(t *testing.T) {
	b := &backend{newSession: func(*smtpd.Conn) error {
		return &smtpd.Error{Code: 554, Enhanced: "5.7.1", Message: "go away"}
	}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	if l := r.line(); l != "554 5.7.1 go away" {
		t.Fatalf("got %q", l)
	}
	r.closed()
}

func TestAPanicInTheBackendClosesOnlyThatConnection(t *testing.T) {
	b := &backend{panicIn: "mail"}
	srv := newServer(b)
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.send("MAIL FROM:<a@x.test>")
	r.closed()
	waitFor(t, "the panic to be counted", func() bool { return srv.Stats().Panics == 1 })

	b.panicIn = ""
	r2 := dial(t, addr)
	r2.hello()
	r2.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestConnectionAddressesAreAvailableToTheBackend(t *testing.T) {
	var got struct {
		remote, local net.Addr
		id            uint64
		sid           string
	}
	b := &backend{newSession: func(c *smtpd.Conn) error {
		got.remote, got.local, got.id, got.sid = c.RemoteAddr(), c.LocalAddr(), c.ID(), c.SessionID()
		if c.RemoteAddrPort().Addr().String() != "127.0.0.1" {
			t.Errorf("RemoteAddrPort = %v", c.RemoteAddrPort())
		}
		if c.Server() == nil {
			t.Error("Server() is nil")
		}
		return nil
	}}
	addr := start(t, newServer(b), false)
	r := dial(t, addr)
	r.hello()
	if got.remote == nil || !strings.HasPrefix(got.remote.String(), "127.0.0.1:") {
		t.Errorf("remote = %v", got.remote)
	}
	if got.local.String() != addr {
		t.Errorf("local = %v, want %v", got.local, addr)
	}
	if got.id == 0 || !strings.Contains(got.sid, "-") {
		t.Errorf("id=%d session=%q", got.id, got.sid)
	}
}

var _ = bytes.NewReader
