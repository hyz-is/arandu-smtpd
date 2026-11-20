package unit_test

import (
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

func TestListenAndServeAndListenAndServeTLS(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		free := listen(t)
		addr := free.Addr().String()
		free.Close()

		var srv *smtpd.Server
		if implicit {
			srv = tlsServer(t, &backend{})
		} else {
			srv = newServer(&backend{})
		}
		errc := make(chan error, 1)
		go func() {
			if implicit {
				errc <- srv.ListenAndServeTLS(addr)
			} else {
				errc <- srv.ListenAndServe(addr)
			}
		}()
		var r *raw
		waitFor(t, "the listener", func() bool {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				return false
			}
			c.Close()
			return true
		})
		if implicit {
			r = dialTLS(t, addr)
		} else {
			r = dial(t, addr)
		}
		r.expect("", "220 ")
		srv.Close()
		if err := <-errc; err != smtpd.ErrServerClosed {
			t.Fatalf("returned %v", err)
		}
	}
	if err := newServer(&backend{}).ListenAndServe("127.0.0.1:-1"); err == nil {
		t.Fatal("a bad address was accepted")
	}
	if err := newServer(&backend{}).ListenAndServeTLS("127.0.0.1:-1"); err == nil {
		t.Fatal("a bad address was accepted")
	}
}

func TestTheSessionKnowsWhoAuthenticated(t *testing.T) {
	var seen string
	b := &backend{users: map[string]string{"api": "k"}, dataHook: nil}
	srv := newServer(smtpd.BackendFunc(func(c *smtpd.Conn) (smtpd.Session, error) {
		return &usernameSession{session: &session{b: b, conn: c}, conn: c, seen: &seen}, nil
	}))
	srv.AllowInsecureAuth = true
	addr := start(t, srv, false)
	r := dial(t, addr)
	r.hello()
	if got := seen; got != "" {
		t.Fatalf("Username before AUTH = %q", got)
	}
	r.expect("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00api\x00k")), "235 ")
	r.transaction("a@x.test", "b@x.test", "Subject: s\r\n\r\nb")
	if seen != "api" {
		t.Fatalf("Username during the message = %q", seen)
	}
}

type usernameSession struct {
	*session
	conn *smtpd.Conn
	seen *string
}

func (s *usernameSession) Data(r io.Reader) error {
	*s.seen = s.conn.Username()
	_, err := io.Copy(io.Discard, r)
	return err
}

func TestUnblockAuthLiftsABlock(t *testing.T) {
	b := &backend{users: map[string]string{"u": "right"}}
	srv := newServer(b)
	srv.AllowInsecureAuth = true
	srv.MaxAuthFailures = 2
	addr := start(t, srv, false)
	bad := base64.StdEncoding.EncodeToString([]byte("\x00u\x00wrong"))
	good := base64.StdEncoding.EncodeToString([]byte("\x00u\x00right"))
	r := dial(t, addr)
	r.hello()
	r.expect("AUTH PLAIN "+bad, "535 ")
	r.expect("AUTH PLAIN "+bad, "535 ")
	r.expect("AUTH PLAIN "+good, "454 ")
	srv.UnblockAuth(netip.MustParseAddr("127.0.0.1"))
	r.expect("AUTH PLAIN "+good, "235 ")
	// Asking about a server that never started is harmless.
	(&smtpd.Server{}).UnblockAuth(netip.MustParseAddr("127.0.0.1"))
}

func TestTheRefuseSessionRefusesDataAndLogsOut(t *testing.T) {
	s := smtpd.RefuseSession{}
	if err := s.Data(strings.NewReader("x")); err == nil {
		t.Error("Data accepted")
	}
	s.Reset()
	if err := s.Logout(); err != nil {
		t.Error(err)
	}
	if e := (&smtpd.Error{Code: 451, Enhanced: "4.3.0", Message: "later"}); !e.Temporary() || e.Error() != "smtp: 451 4.3.0 later" {
		t.Errorf("Error() = %q", e.Error())
	}
	if (&smtpd.Error{Code: 550}).Temporary() {
		t.Error("a 550 is temporary")
	}
}

func TestIPv6ClientsAreCountedByTheirSlash64(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	srv := newServer(&backend{})
	srv.MaxConnectionsPerIP = 2
	addr := startOn(t, srv, l, false)
	a, b := dial(t, addr), dial(t, addr)
	a.expect("", "220 ")
	b.expect("", "220 ")
	c := dial(t, addr)
	if l := c.line(); !strings.HasPrefix(l, "421 4.7.0") {
		t.Fatalf("got %q", l)
	}
}
