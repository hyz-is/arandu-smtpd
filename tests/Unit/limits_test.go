package unit_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

func TestMaxConnectionsRefusesTheOneOverTheLimit(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxConnections = 2
	addr := start(t, srv, false)

	a, b := dial(t, addr), dial(t, addr)
	a.expect("", "220 ")
	b.expect("", "220 ")
	c := dial(t, addr)
	if l := c.line(); !strings.HasPrefix(l, "421 4.3.2") {
		t.Fatalf("got %q, want a 421 4.3.2", l)
	}
	c.closed()
	if srv.Stats().ConnsRefused != 1 {
		t.Fatalf("ConnsRefused = %d", srv.Stats().ConnsRefused)
	}

	a.conn.Close()
	waitFor(t, "the slot to be free", func() bool { return srv.Stats().ConnsActive == 1 })
	d := dial(t, addr)
	d.expect("", "220 ")
}

func TestMaxConnectionsPerIP(t *testing.T) {
	srv := newServer(&backend{})
	srv.MaxConnectionsPerIP = 2
	addr := start(t, srv, false)

	a, b := dial(t, addr), dial(t, addr)
	a.expect("", "220 ")
	b.expect("", "220 ")
	c := dial(t, addr)
	if l := c.line(); !strings.HasPrefix(l, "421 4.7.0") {
		t.Fatalf("got %q, want a 421 4.7.0", l)
	}
	c.closed()

	b.conn.Close()
	var d *raw
	waitFor(t, "the per-IP slot to be free", func() bool {
		d = dial(t, addr)
		return strings.HasPrefix(d.line(), "220 ")
	})
}

func TestTheDefaultsLimitEverything(t *testing.T) {
	// The zero Server limits connections per client; a negative number turns
	// that off. 100 is the default, so 100 get in and the 101st does not.
	srv := &smtpd.Server{Backend: smtpd.RefuseBackend{}, AuthFailureDelay: -1}
	addr := start(t, srv, false)
	var held []*raw
	for i := 0; i < 100; i++ {
		r := dial(t, addr)
		r.expect("", "220 ")
		held = append(held, r)
	}
	r := dial(t, addr)
	if l := r.line(); !strings.HasPrefix(l, "421 ") {
		t.Fatalf("the 101st connection got %q", l)
	}
	_ = held
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestFailedAuthBlocksTheClientAndThenLetsItBack(t *testing.T) {
	b := &backend{users: map[string]string{"u": "right"}}
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	srv.MaxAuthFailures = 3
	srv.AuthFailureWindow = time.Minute
	srv.AuthBlockDuration = time.Hour
	srv.Now = clk.now
	addr := start(t, srv, false)

	bad := base64.StdEncoding.EncodeToString([]byte("\x00u\x00wrong"))
	good := base64.StdEncoding.EncodeToString([]byte("\x00u\x00right"))

	r := dial(t, addr)
	r.hello()
	r.expect("AUTH PLAIN "+bad, "535 ")
	r.expect("AUTH PLAIN "+bad, "535 ")
	r.expect("AUTH PLAIN "+bad, "535 ")
	// Blocked now, on this connection and on any other, even with the right one.
	r.expect("AUTH PLAIN "+good, "454 4.7.0")
	r2 := dial(t, addr)
	r2.hello()
	r2.expect("AUTH PLAIN "+good, "454 4.7.0")
	if b.authCalls != 3 {
		t.Fatalf("the Session was asked %d times; the blocked attempts must not reach it", b.authCalls)
	}
	if s := srv.Stats(); s.AuthFailure != 3 || s.AuthBlocked != 2 {
		t.Fatalf("stats = %+v", s)
	}

	clk.advance(2 * time.Hour)
	r2.expect("AUTH PLAIN "+good, "235 ")
}

func TestFailuresOutsideTheWindowDoNotAddUp(t *testing.T) {
	b := &backend{users: map[string]string{"u": "right"}}
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	srv.MaxAuthFailures = 3
	srv.AuthFailureWindow = time.Minute
	srv.Now = clk.now
	addr := start(t, srv, false)
	bad := base64.StdEncoding.EncodeToString([]byte("\x00u\x00wrong"))
	good := base64.StdEncoding.EncodeToString([]byte("\x00u\x00right"))
	r := dial(t, addr)
	r.hello()
	for i := 0; i < 5; i++ {
		r.expect("AUTH PLAIN "+bad, "535 ")
		clk.advance(2 * time.Minute)
	}
	r.expect("AUTH PLAIN "+good, "235 ")
}

func TestAFailedAuthIsAnsweredAfterAPauseThatGrows(t *testing.T) {
	b := &backend{users: map[string]string{"u": "right"}}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	srv.AuthFailureDelay = 80 * time.Millisecond
	srv.AuthFailureDelayMax = 200 * time.Millisecond
	srv.MaxAuthFailures = -1
	addr := start(t, srv, false)
	bad := base64.StdEncoding.EncodeToString([]byte("\x00u\x00wrong"))
	r := dial(t, addr)
	r.hello()

	took := func() time.Duration {
		start := time.Now()
		r.expect("AUTH PLAIN "+bad, "535 ")
		return time.Since(start)
	}
	if d := took(); d < 80*time.Millisecond {
		t.Errorf("first failure answered after %v, want at least 80ms", d)
	}
	if d := took(); d < 160*time.Millisecond {
		t.Errorf("second failure answered after %v, want at least 160ms", d)
	}
	if d := took(); d < 200*time.Millisecond || d > 2*time.Second {
		t.Errorf("third failure answered after %v, want the 200ms cap", d)
	}
}

func TestEarlyTalkersAreRefused(t *testing.T) {
	srv := newServer(&backend{})
	srv.EarlyTalkerDelay = 150 * time.Millisecond
	addr := start(t, srv, false)

	r := dial(t, addr)
	r.write("EHLO impatient\r\n")
	if l := r.line(); !strings.HasPrefix(l, "554 5.5.0") {
		t.Fatalf("got %q, want a 554 5.5.0", l)
	}
	r.closed()
	if srv.Stats().EarlyTalkers != 1 {
		t.Fatalf("EarlyTalkers = %d", srv.Stats().EarlyTalkers)
	}

	// A client that waits gets its greeting, after the delay.
	began := time.Now()
	p := dial(t, addr)
	p.expect("", "220 ")
	if d := time.Since(began); d < 150*time.Millisecond {
		t.Errorf("the greeting came after %v, before the early-talker delay", d)
	}
	p.expect("EHLO polite", "250 ")
	p.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
}

func TestEarlyTalkerCheckOnImplicitTLS(t *testing.T) {
	srv := tlsServer(t, &backend{})
	srv.EarlyTalkerDelay = 100 * time.Millisecond
	addr := start(t, srv, true)

	// Waiting works.
	p := dialTLS(t, addr)
	p.expect("", "220 ")
	p.expect("EHLO polite", "250 ")

	// Speaking inside the tunnel before the greeting does not.
	c, err := tls.Dial("tcp", addr, clientTLS())
	if err != nil {
		t.Fatal(err)
	}
	r := &raw{t: t, conn: c, br: bufio.NewReader(c)}
	defer c.Close()
	r.write("EHLO impatient\r\n")
	if l := r.line(); !strings.HasPrefix(l, "554 5.5.0") {
		t.Fatalf("got %q", l)
	}
}

func proxyV1(src, dst string, sport, dport int) string {
	proto := "TCP4"
	if strings.Contains(src, ":") {
		proto = "TCP6"
	}
	return "PROXY " + proto + " " + src + " " + dst + " " + strconv.Itoa(sport) + " " + strconv.Itoa(dport) + "\r\n"
}

func proxyV2(src, dst netip.AddrPort, command byte) []byte {
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	var addrs []byte
	family := byte(0)
	if src.IsValid() {
		if src.Addr().Is4() {
			family = 0x11
			a, d := src.Addr().As4(), dst.Addr().As4()
			addrs = append(a[:], d[:]...)
			addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
			addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
		} else {
			family = 0x21
			a, d := src.Addr().As16(), dst.Addr().As16()
			addrs = append(a[:], d[:]...)
			addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
			addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
		}
	}
	out := append(sig, 0x20|command, family)
	out = binary.BigEndian.AppendUint16(out, uint16(len(addrs)+3))
	out = append(out, addrs...)
	return append(out, 0xEE, 0x00, 0x00) // a TLV the server must skip: type 0xEE, length 0
}

func proxied(t *testing.T, b smtpd.Backend, mutate func(*smtpd.Server)) (string, *smtpd.Server) {
	srv := newServer(b)
	srv.ProxyProtocol = true
	if mutate != nil {
		mutate(srv)
	}
	return start(t, srv, false), srv
}

func TestProxyProtocolV1GivesTheBackendTheRealAddress(t *testing.T) {
	b := &backend{}
	addr, srv := proxied(t, b, nil)
	r := dial(t, addr)
	r.write(proxyV1("203.0.113.9", "192.0.2.1", 5555, 25))
	r.expect("", "220 ")
	r.expect("EHLO c.test", "250 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if got := b.all()[0].Remote; got != "203.0.113.9:5555" {
		t.Fatalf("RemoteAddr = %q", got)
	}
	if srv.Stats().ProxyHeaders != 1 {
		t.Fatalf("ProxyHeaders = %d", srv.Stats().ProxyHeaders)
	}
}

func TestProxyProtocolV1WithIPv6AndUnknown(t *testing.T) {
	b := &backend{}
	addr, _ := proxied(t, b, nil)
	r := dial(t, addr)
	r.write(proxyV1("2001:db8::1", "2001:db8::2", 4000, 25))
	r.expect("", "220 ")
	r.expect("EHLO c.test", "250 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if got := b.all()[0].Remote; got != "[2001:db8::1]:4000" {
		t.Fatalf("RemoteAddr = %q", got)
	}

	r2 := dial(t, addr)
	r2.write("PROXY UNKNOWN\r\n")
	r2.expect("", "220 ")
	r2.expect("EHLO c.test", "250 ")
	r2.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if got := b.all()[1].Remote; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("RemoteAddr = %q, want the socket's", got)
	}
}

func TestProxyProtocolV2(t *testing.T) {
	b := &backend{}
	addr, _ := proxied(t, b, nil)

	r := dial(t, addr)
	r.write(string(proxyV2(netip.MustParseAddrPort("198.51.100.7:6000"), netip.MustParseAddrPort("192.0.2.1:25"), 1)))
	r.expect("", "220 ")
	r.expect("EHLO c.test", "250 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if got := b.all()[0].Remote; got != "198.51.100.7:6000" {
		t.Fatalf("RemoteAddr = %q", got)
	}

	r6 := dial(t, addr)
	r6.write(string(proxyV2(netip.MustParseAddrPort("[2001:db8::7]:6001"), netip.MustParseAddrPort("[2001:db8::1]:25"), 1)))
	r6.expect("", "220 ")
	r6.expect("EHLO c.test", "250 ")
	r6.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if got := b.all()[1].Remote; got != "[2001:db8::7]:6001" {
		t.Fatalf("RemoteAddr = %q", got)
	}

	// LOCAL: a health check from the balancer itself.
	rl := dial(t, addr)
	rl.write(string(proxyV2(netip.AddrPort{}, netip.AddrPort{}, 0)))
	rl.expect("", "220 ")
}

func TestConnectionsWithoutAProxyHeaderAreDropped(t *testing.T) {
	addr, srv := proxied(t, &backend{}, nil)
	r := dial(t, addr)
	r.write("EHLO c.test\r\n")
	r.closed()
	waitFor(t, "the failure to be counted", func() bool { return srv.Stats().ProxyFailures == 1 })

	r2 := dial(t, addr)
	r2.write("PROXY TCP4 not-an-address 1.2.3.4 1 2\r\n")
	r2.closed()
	r3 := dial(t, addr)
	r3.write("PROXY " + strings.Repeat("x", 200))
	r3.closed()
}

func TestAProxyHeaderIsOnlyBelievedFromTrustedPeers(t *testing.T) {
	addr, srv := proxied(t, &backend{}, func(s *smtpd.Server) {
		s.ProxyTrusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	r := dial(t, addr)
	r.write(proxyV1("203.0.113.9", "192.0.2.1", 1, 25))
	r.closed()
	if srv.Stats().ProxyFailures != 1 {
		t.Fatalf("ProxyFailures = %d", srv.Stats().ProxyFailures)
	}

	addr2, _ := proxied(t, &backend{}, func(s *smtpd.Server) {
		s.ProxyTrusted = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	})
	ok := dial(t, addr2)
	ok.write(proxyV1("203.0.113.9", "192.0.2.1", 1, 25))
	ok.expect("", "220 ")
}

func TestPerIPLimitCountsTheProxiedAddress(t *testing.T) {
	addr, _ := proxied(t, &backend{}, func(s *smtpd.Server) { s.MaxConnectionsPerIP = 1 })
	a := dial(t, addr)
	a.write(proxyV1("203.0.113.1", "192.0.2.1", 1, 25))
	a.expect("", "220 ")
	b := dial(t, addr)
	b.write(proxyV1("203.0.113.2", "192.0.2.1", 1, 25))
	b.expect("", "220 ")
	c := dial(t, addr)
	c.write(proxyV1("203.0.113.1", "192.0.2.1", 2, 25))
	if l := c.line(); !strings.HasPrefix(l, "421 4.7.0") {
		t.Fatalf("got %q", l)
	}
}

// headerConn writes a PROXY header and the first bytes the client sends in one
// packet, so the server reads both at once.
type headerConn struct {
	net.Conn
	header []byte
	sent   bool
}

func (c *headerConn) Write(p []byte) (int, error) {
	if !c.sent {
		c.sent = true
		if _, err := c.Conn.Write(append(append([]byte(nil), c.header...), p...)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func TestProxyProtocolInFrontOfImplicitTLS(t *testing.T) {
	b := &backend{}
	srv := tlsServer(t, b)
	srv.ProxyProtocol = true
	addr := start(t, srv, true)

	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	hc := &headerConn{Conn: nc, header: []byte(proxyV1("203.0.113.50", "192.0.2.1", 7000, 465))}
	tc := tls.Client(hc, clientTLS())
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	r := &raw{t: t, conn: tc, br: bufio.NewReader(tc)}
	defer tc.Close()
	r.expect("", "220 ")
	r.expect("EHLO c.test", "250 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if m := b.all()[0]; m.Remote != "203.0.113.50:7000" || !m.TLS {
		t.Fatalf("remote=%q tls=%v", m.Remote, m.TLS)
	}
}

func TestShutdownHangsUpOnIdleConnectionsAndLetsAMessageFinish(t *testing.T) {
	b := &backend{}
	srv := newServer(b)
	l := listen(t)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	addr := l.Addr().String()

	idle := dial(t, addr)
	idle.hello()

	busy := dial(t, addr)
	busy.hello()
	busy.expect("MAIL FROM:<a@x.test>", "250 ")
	busy.expect("RCPT TO:<b@x.test>", "250 ")
	busy.expect("DATA", "354 ")
	busy.write("Subject: slow\r\n\r\nfirst half\r\n")

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- srv.Shutdown(ctx)
	}()

	if l := idle.line(); !strings.HasPrefix(l, "421 4.3.2") {
		t.Fatalf("the idle connection got %q, want a 421 4.3.2", l)
	}
	idle.closed()

	select {
	case err := <-done:
		t.Fatalf("Shutdown returned (%v) while a message was in progress", err)
	case <-time.After(150 * time.Millisecond):
	}

	// The message in progress finishes, and then the server says goodbye.
	busy.write("second half\r\n.\r\n")
	busy.expect("", "250 ")
	if l := busy.line(); !strings.HasPrefix(l, "421 4.3.2") {
		t.Fatalf("after the message got %q, want a 421 4.3.2", l)
	}
	busy.closed()

	if err := <-done; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-errc; err != smtpd.ErrServerClosed {
		t.Fatalf("Serve = %v, want ErrServerClosed", err)
	}
	if got := string(b.all()[0].Data); got != "Subject: slow\r\n\r\nfirst half\r\nsecond half\r\n" {
		t.Fatalf("Data = %q", got)
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("the listener is still open")
	}
}

func TestShutdownGivesUpWhenTheContextEnds(t *testing.T) {
	srv := newServer(&backend{})
	l := listen(t)
	go srv.Serve(l)
	addr := l.Addr().String()
	busy := dial(t, addr)
	busy.hello()
	busy.expect("MAIL FROM:<a@x.test>", "250 ")
	busy.expect("RCPT TO:<b@x.test>", "250 ")
	busy.expect("DATA", "354 ")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); err != context.DeadlineExceeded {
		t.Fatalf("Shutdown = %v, want DeadlineExceeded", err)
	}
	busy.closed()
	if srv.Stats().ConnsActive != 0 {
		t.Fatalf("ConnsActive = %d", srv.Stats().ConnsActive)
	}
}

func TestCloseEndsEverythingAtOnce(t *testing.T) {
	srv := newServer(&backend{})
	l := listen(t)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	r := dial(t, l.Addr().String())
	r.hello()
	srv.Close()
	r.closed()
	if err := <-errc; err != smtpd.ErrServerClosed {
		t.Fatalf("Serve = %v", err)
	}
	if err := srv.Serve(listen(t)); err != smtpd.ErrServerClosed {
		t.Fatalf("Serve after Close = %v", err)
	}
}

func TestAnIdleConnectionTimesOut(t *testing.T) {
	srv := newServer(&backend{})
	srv.CommandTimeout = 100 * time.Millisecond
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.expect("", "220 ")
	if l := r.line(); !strings.HasPrefix(l, "421 4.4.2") {
		t.Fatalf("got %q, want a 421 4.4.2", l)
	}
	r.closed()
	if srv.Stats().Timeouts != 1 {
		t.Fatalf("Timeouts = %d", srv.Stats().Timeouts)
	}
}

func TestASlowMessageTimesOut(t *testing.T) {
	srv := newServer(&backend{})
	srv.DataTimeout = 200 * time.Millisecond
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("DATA", "354 ")
	// One byte every 100 ms never finishes inside 200 ms in total.
	for i := 0; i < 10; i++ {
		if _, err := io.WriteString(r.conn, "x"); err != nil {
			break
		}
		time.Sleep(60 * time.Millisecond)
	}
	r.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(r.br)
	if !strings.Contains(string(got), "421 4.4.2") {
		t.Fatalf("got %q, want a 421 4.4.2", got)
	}
}

func TestStatsCountWhatHappened(t *testing.T) {
	b := &backend{rcptErr: map[string]error{"no@x.test": smtpd.ErrMailboxUnavailable}}
	srv := newServer(b)
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("MAIL FROM:<a@x.test>", "250 ")
	r.expect("RCPT TO:<b@x.test>", "250 ")
	r.expect("RCPT TO:<no@x.test>", "550 ")
	r.expect("BOGUS", "500 ")
	r.expect("DATA", "354 ")
	r.write("Subject: s\r\n\r\nbody\r\n.\r\n")
	r.expect("", "250 ")
	r.expect("QUIT", "221 ")
	waitFor(t, "the connection to close", func() bool { return srv.Stats().ConnsActive == 0 })

	s := srv.Stats()
	want := smtpd.Stats{
		ConnsAccepted: 1, ConnsActive: 0, Sessions: 1, Commands: 7, ProtocolErrors: 2,
		Messages: 1, DataBytes: int64(len("Subject: s\r\n\r\nbody\r\n")), RcptAccepted: 1, RcptRefused: 1,
	}
	if s != want {
		t.Fatalf("Stats = %+v\nwant   %+v", s, want)
	}
}

func TestLogRecordsCarryTheConnectionAndSessionIDs(t *testing.T) {
	var buf lockedBuffer
	b := &backend{}
	srv := newServer(b)
	srv.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	r.expect("QUIT", "221 ")
	waitFor(t, "the close record", func() bool { return strings.Contains(buf.String(), "connection closed") })

	var sessions, conns = map[string]bool{}, map[float64]bool{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		sessions[rec["session"].(string)] = true
		conns[rec["conn"].(float64)] = true
		if !strings.HasPrefix(rec["remote"].(string), "127.0.0.1:") {
			t.Errorf("remote = %v", rec["remote"])
		}
	}
	if len(sessions) != 1 || len(conns) != 1 {
		t.Fatalf("records for %d sessions and %d connections, want 1 and 1", len(sessions), len(conns))
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestManyConnectionsAtOnceDeliverEveryMessage(t *testing.T) {
	b := &backend{discard: true}
	var delivered atomic.Int64
	b.dataHook = func(r io.Reader) error {
		n, err := io.Copy(io.Discard, r)
		if err == nil && n > 0 {
			delivered.Add(1)
		}
		return err
	}
	srv := newServer(b)
	srv.MaxConnections = -1
	addr := start(t, srv, false)
	const workers, each = 40, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			r := &raw{t: t, conn: c, br: bufio.NewReader(c)}
			r.expect("", "220 ")
			r.expect("EHLO c.test", "250 ")
			for i := 0; i < each; i++ {
				r.transaction("a@x.test", "b@x.test", "Subject: load\r\n\r\nbody")
			}
		}()
	}
	wg.Wait()
	if got := delivered.Load(); got != workers*each {
		t.Fatalf("delivered %d, want %d", got, workers*each)
	}
	if s := srv.Stats(); s.Messages != workers*each {
		t.Fatalf("Messages = %d", s.Messages)
	}
}
