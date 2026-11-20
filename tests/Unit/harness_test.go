package unit_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

// message is what the test backend received.
type message struct {
	From       string
	MailOpts   smtpd.MailOptions
	Rcpts      []string
	RcptOpts   []smtpd.RcptOptions
	Data       []byte
	User       string
	Remote     string
	Hostname   string
	TLS        bool
	SessionID  string
	ConnID     uint64
	DataReadOK bool
}

// backend is a Backend that records what it is given. Its behaviour is set by
// the fields before the server starts.
type backend struct {
	mu       sync.Mutex
	messages []message

	users      map[string]string         // username -> password; empty means every Auth fails
	rcptErr    map[string]error          // recipient -> the error Rcpt returns
	mailErr    error                     // returned from Mail
	dataErr    error                     // returned from Data after reading
	dataHook   func(r io.Reader) error   // replaces the default Data
	discard    bool                      // read and drop the message without storing it
	panicIn    string                    // "mail" makes Mail panic
	newSession func(c *smtpd.Conn) error // runs in NewSession
	onReset    func()                    // runs in Reset
	resets     int
	logouts    int
	authCalls  int
}

func (b *backend) NewSession(c *smtpd.Conn) (smtpd.Session, error) {
	if b.newSession != nil {
		if err := b.newSession(c); err != nil {
			return nil, err
		}
	}
	return &session{b: b, conn: c}, nil
}

func (b *backend) all() []message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]message(nil), b.messages...)
}

func (b *backend) counts() (resets, logouts int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.resets, b.logouts
}

type session struct {
	b    *backend
	conn *smtpd.Conn
	cur  message
	user string
}

func (s *session) Auth(mechanism, username, password string) error {
	s.b.mu.Lock()
	s.b.authCalls++
	pw, ok := s.b.users[username]
	s.b.mu.Unlock()
	if !ok || pw != password {
		return smtpd.ErrAuthFailed
	}
	s.user = username
	return nil
}

func (s *session) Mail(from string, opts *smtpd.MailOptions) error {
	if s.b.panicIn == "mail" {
		panic("the backend broke")
	}
	if s.b.mailErr != nil {
		return s.b.mailErr
	}
	s.cur = message{From: from, MailOpts: *opts}
	return nil
}

func (s *session) Rcpt(to string, opts *smtpd.RcptOptions) error {
	if err, ok := s.b.rcptErr[to]; ok {
		return err
	}
	s.cur.Rcpts = append(s.cur.Rcpts, to)
	o := *opts
	o.Notify = append([]smtpd.DSNNotify(nil), opts.Notify...)
	s.cur.RcptOpts = append(s.cur.RcptOpts, o)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if s.b.dataHook != nil {
		return s.b.dataHook(r)
	}
	if s.b.discard {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if s.b.dataErr != nil {
		return s.b.dataErr
	}
	m := s.cur
	m.Data = data
	m.User = s.user
	m.Remote = s.conn.RemoteAddr().String()
	m.Hostname = s.conn.Hostname()
	_, m.TLS = s.conn.TLS()
	m.SessionID = s.conn.SessionID()
	m.ConnID = s.conn.ID()
	s.b.mu.Lock()
	s.b.messages = append(s.b.messages, m)
	s.b.mu.Unlock()
	return nil
}

func (s *session) Reset() {
	s.b.mu.Lock()
	s.b.resets++
	s.b.mu.Unlock()
	if s.b.onReset != nil {
		s.b.onReset()
	}
	s.cur = message{}
}

func (s *session) Logout() error {
	s.b.mu.Lock()
	s.b.logouts++
	s.b.mu.Unlock()
	return nil
}

// testCert makes a self-signed certificate for localhost and returns it with the
// PEM of the certificate and of the key.
func testCert(t testing.TB, serial int64) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPEM, keyPEM
}

func clientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}
}

// listen opens a loopback listener.
func listen(t testing.TB) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// start runs srv on a new listener (implicit TLS when implicit is set) and stops
// it when the test ends. It returns the address.
func start(t testing.TB, srv *smtpd.Server, implicit bool) string {
	t.Helper()
	l := listen(t)
	return startOn(t, srv, l, implicit)
}

func startOn(t testing.TB, srv *smtpd.Server, l net.Listener, implicit bool) string {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		if implicit {
			errc <- srv.ServeTLS(l)
		} else {
			errc <- srv.Serve(l)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		if err := <-errc; err != nil && !errors.Is(err, smtpd.ErrServerClosed) {
			t.Errorf("Serve returned %v", err)
		}
	})
	return l.Addr().String()
}

// newServer is a Server with the limits that would slow a test down turned off.
func newServer(b smtpd.Backend) *smtpd.Server {
	return &smtpd.Server{
		Backend:             b,
		Hostname:            "mx.test",
		AuthFailureDelay:    -1,
		MaxConnectionsPerIP: -1,
	}
}

func tlsServer(t testing.TB, b smtpd.Backend) *smtpd.Server {
	t.Helper()
	pair, _, _ := testCert(t, 1)
	srv := newServer(b)
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}}
	return srv
}

// raw is a plain client that speaks SMTP one line at a time.
type raw struct {
	t    testing.TB
	conn net.Conn
	br   *bufio.Reader
}

func dial(t testing.TB, addr string) *raw {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := &raw{t: t, conn: c, br: bufio.NewReader(c)}
	t.Cleanup(func() { r.conn.Close() })
	return r
}

func dialTLS(t testing.TB, addr string) *raw {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, clientTLS())
	if err != nil {
		t.Fatal(err)
	}
	r := &raw{t: t, conn: c, br: bufio.NewReader(c)}
	t.Cleanup(func() { r.conn.Close() })
	return r
}

// line reads one reply line, failing the test if none arrives.
func (r *raw) line() string {
	r.t.Helper()
	r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	s, err := r.br.ReadString('\n')
	if err != nil {
		r.t.Fatalf("reading a reply: %v (got %q)", err, s)
	}
	return strings.TrimRight(s, "\r\n")
}

// reply reads a whole reply, continuation lines included, and returns its lines.
func (r *raw) reply() []string {
	r.t.Helper()
	var lines []string
	for {
		l := r.line()
		lines = append(lines, l)
		if len(l) < 4 || l[3] != '-' {
			return lines
		}
	}
}

// send writes s followed by CRLF.
func (r *raw) send(s string) {
	r.t.Helper()
	r.write(s + "\r\n")
}

func (r *raw) write(s string) {
	r.t.Helper()
	r.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(r.conn, s); err != nil {
		r.t.Fatalf("writing: %v", err)
	}
}

// expect sends cmd, reads the reply and requires its last line to start with
// prefix.
func (r *raw) expect(cmd, prefix string) []string {
	r.t.Helper()
	if cmd != "" {
		r.send(cmd)
	}
	lines := r.reply()
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, prefix) {
		r.t.Fatalf("after %q: got %q, want a reply starting %q", cmd, last, prefix)
	}
	return lines
}

// closed requires the server to close the connection, optionally after a last
// reply which it returns.
func (r *raw) closed() {
	r.t.Helper()
	r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.br.ReadByte(); err == nil {
		r.t.Fatal("the connection is still open and sent more data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		r.t.Fatal("the server did not close the connection")
	}
}

// hello greets and returns the EHLO lines.
func (r *raw) hello() []string {
	r.t.Helper()
	r.expect("", "220 ")
	return r.expect("EHLO client.test", "250 ")
}

// transaction runs MAIL, RCPT and DATA with body and requires a 250.
func (r *raw) transaction(from, to, body string) {
	r.t.Helper()
	r.expect("MAIL FROM:<"+from+">", "250 ")
	r.expect("RCPT TO:<"+to+">", "250 ")
	r.expect("DATA", "354 ")
	r.write(body + "\r\n.\r\n")
	r.expect("", "250 ")
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if len(l) > 4 && strings.EqualFold(l[4:], want) {
			return true
		}
	}
	return false
}

func hasPrefixLine(lines []string, prefix string) bool {
	for _, l := range lines {
		if len(l) > 4 && strings.HasPrefix(strings.ToUpper(l[4:]), strings.ToUpper(prefix)) {
			return true
		}
	}
	return false
}

// waitFor polls until cond is true.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// packageRoot is the directory that holds go.mod.
func packageRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find the test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readFile(t testing.TB, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var _ = bytes.Equal
var _ = fmt.Sprint
