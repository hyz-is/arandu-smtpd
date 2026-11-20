package smtpd_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	smtpd "github.com/hyz-is/arandu-smtpd"
)

// submission is the Session of a relay that takes a message from a client that
// authenticates with an API key as its password and hands it to the
// application.
type submission struct {
	smtpd.RefuseSession // everything not overridden below is refused
	key                 string
	from                string
	rcpts               []string
}

func (s *submission) Auth(mechanism, username, password string) error {
	if username != "api" || len(password) < 16 {
		return smtpd.ErrAuthFailed
	}
	s.key = password // the application checks the key against its store here
	return nil
}

func (s *submission) Mail(from string, opts *smtpd.MailOptions) error {
	if s.key == "" {
		return smtpd.ErrAuthRequired
	}
	s.from = from
	return nil
}

func (s *submission) Rcpt(to string, opts *smtpd.RcptOptions) error {
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *submission) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r) // parse and forward the message
	return err
}

func (s *submission) Reset() { s.from, s.rcpts = "", s.rcpts[:0] }

// A submission relay: TLS from the first byte on 465 and 2465, STARTTLS on 587
// and 2587, the password is the API key, and nobody authenticates in the clear.
func ExampleServer_submission() {
	reloader, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{
		CertFile: "/certs/server.crt",
		KeyFile:  "/certs/server.key",
		Logger:   slog.Default(),
	})
	if err != nil {
		slog.Error("certificate", "error", err)
		return
	}
	reloader.Start(context.Background())
	defer reloader.Close()

	srv := &smtpd.Server{
		Backend: smtpd.BackendFunc(func(*smtpd.Conn) (smtpd.Session, error) {
			return &submission{}, nil
		}),
		Hostname:        "relay.example.com",
		TLSConfig:       reloader.TLSConfig(),
		RequireAuth:     true,
		MaxMessageBytes: 10 << 20,
		MaxRecipients:   50,
		Logger:          slog.Default(),
	}
	for _, port := range []string{":465", ":2465"} {
		go srv.ListenAndServeTLS(port)
	}
	for _, port := range []string{":587", ":2587"} {
		go srv.ListenAndServe(port)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// mx is the Session of a server that receives mail for its own domain only.
type mx struct {
	smtpd.RefuseSession
	domain string
}

func (m *mx) Rcpt(to string, _ *smtpd.RcptOptions) error {
	if !hasDomain(to, m.domain) {
		return smtpd.ErrRelayDenied // never an open relay
	}
	return nil
}

func (m *mx) Mail(string, *smtpd.MailOptions) error { return nil }

func (m *mx) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r) // a bounce report or a complaint
	return err
}

func hasDomain(addr, domain string) bool {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return addr[i+1:] == domain
		}
	}
	return false
}

// An inbound server for the return-path domain, behind a load balancer that
// speaks the PROXY protocol, with no AUTH at all.
func ExampleServer_inbound() {
	srv := &smtpd.Server{
		Backend: smtpd.BackendFunc(func(*smtpd.Conn) (smtpd.Session, error) {
			return &mx{domain: "bounces.example.com"}, nil
		}),
		Hostname:         "mx.example.com",
		DisableAuth:      true,
		ProxyProtocol:    true,
		EarlyTalkerDelay: 500 * time.Millisecond,
		RejectBareLF:     true,
		MaxMessageBytes:  1 << 20,
	}
	l, err := net.Listen("tcp", ":25")
	if err != nil {
		return
	}
	srv.Serve(l)
}
