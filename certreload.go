package smtpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// CertReloaderConfig configures a CertReloader.
type CertReloaderConfig struct {
	// CertFile and KeyFile are the PEM files of the certificate chain and of
	// its private key. Required.
	CertFile string
	KeyFile  string
	// Interval is how often Start polls the files. The default is 5 minutes;
	// the shortest accepted is 1 second and the longest is 24 hours.
	Interval time.Duration
	// ExpiryWarning is how long before the certificate expires the reloader
	// starts logging a warning on every check. The default is 14 days.
	ExpiryWarning time.Duration
	// Logger receives the reloader's records. The default discards them.
	Logger *slog.Logger
	// Now is the clock the expiry check reads. It is for tests.
	Now func() time.Time
}

// CertResult is the outcome of one CertReloader.Check.
type CertResult int

// The outcomes of a check.
const (
	// CertUnchanged means the files hold what is already served.
	CertUnchanged CertResult = iota
	// CertReloaded means a new certificate is being served.
	CertReloaded
	// CertFailed means the files could not be read, or do not form a valid pair,
	// and the certificate that was being served still is.
	CertFailed
)

// String names the outcome.
func (r CertResult) String() string {
	switch r {
	case CertUnchanged:
		return "unchanged"
	case CertReloaded:
		return "reloaded"
	}
	return "failed"
}

// CertReloader serves a TLS certificate from files and replaces it when the
// files change, so a renewed certificate reaches new connections without a
// restart. Use its GetCertificate as tls.Config.GetCertificate.
//
// It compares the content of the files, not their modification times, and
// reads the paths again on every check: a renewal that swaps a symlink (as
// certbot's live/ directory does) is seen, which a watcher on the old file
// would miss. A pair that does not parse, or whose key does not belong to the
// certificate (a renewal caught half-written), is refused and the certificate in
// use stays.
type CertReloader struct {
	cfg CertReloaderConfig
	log *slog.Logger
	now func() time.Time

	cur atomic.Pointer[certState]

	checkMu sync.Mutex

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	stopped   chan struct{}
}

type certState struct {
	cert     *tls.Certificate
	certPEM  []byte
	keyPEM   []byte
	notAfter time.Time
}

// NewCertReloader loads the certificate and returns the reloader that serves
// it. It fails when the first load does, so a bad path is found at start.
func NewCertReloader(cfg CertReloaderConfig) (*CertReloader, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("smtpd: CertReloaderConfig needs CertFile and KeyFile")
	}
	cfg.Interval = orDefault(cfg.Interval, 5*time.Minute)
	cfg.Interval = min(max(cfg.Interval, time.Second), 24*time.Hour)
	cfg.ExpiryWarning = orDefault(cfg.ExpiryWarning, 14*24*time.Hour)
	r := &CertReloader{
		cfg:     cfg,
		log:     cfg.Logger,
		now:     cfg.Now,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.now == nil {
		r.now = time.Now
	}
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	r.cur.Store(st)
	r.log.Info("smtpd: TLS certificate loaded", slog.Time("not_after", st.notAfter))
	r.warnIfExpiring(st)
	return r, nil
}

func (r *CertReloader) load() (*certState, error) {
	certPEM, err := os.ReadFile(r.cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("smtpd: reading the certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(r.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("smtpd: reading the private key: %w", err)
	}
	return parseCertState(certPEM, keyPEM)
}

func parseCertState(certPEM, keyPEM []byte) (*certState, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("smtpd: the certificate and key do not form a pair: %w", err)
	}
	if pair.Leaf == nil {
		return nil, errors.New("smtpd: the certificate has no leaf")
	}
	return &certState{cert: &pair, certPEM: certPEM, keyPEM: keyPEM, notAfter: pair.Leaf.NotAfter}, nil
}

// GetCertificate returns the certificate in use. It is the function to put in
// tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cur.Load().cert, nil
}

// TLSConfig returns a tls.Config that serves this reloader's certificate, with
// TLS 1.2 as the lowest version.
func (r *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
}

// NotAfter is when the certificate in use expires.
func (r *CertReloader) NotAfter() time.Time { return r.cur.Load().notAfter }

// Check reads the files once and swaps the certificate in if they changed. On
// CertFailed the error says why; the previous certificate is still served.
func (r *CertReloader) Check() (CertResult, error) {
	r.checkMu.Lock()
	defer r.checkMu.Unlock()
	cur := r.cur.Load()

	certPEM, err := os.ReadFile(r.cfg.CertFile)
	if err == nil {
		var keyPEM []byte
		if keyPEM, err = os.ReadFile(r.cfg.KeyFile); err == nil {
			if bytes.Equal(certPEM, cur.certPEM) && bytes.Equal(keyPEM, cur.keyPEM) {
				r.warnIfExpiring(cur)
				return CertUnchanged, nil
			}
			var next *certState
			if next, err = parseCertState(certPEM, keyPEM); err == nil {
				r.cur.Store(next)
				r.log.Info("smtpd: TLS certificate reloaded", slog.Time("not_after", next.notAfter))
				r.warnIfExpiring(next)
				return CertReloaded, nil
			}
		}
	}
	r.log.Error("smtpd: could not load the renewed TLS certificate, keeping the current one", slog.String("error", err.Error()))
	r.warnIfExpiring(cur)
	return CertFailed, err
}

func (r *CertReloader) warnIfExpiring(st *certState) {
	left := st.notAfter.Sub(r.now())
	switch {
	case left <= 0:
		r.log.Error("smtpd: the TLS certificate has expired", slog.Time("not_after", st.notAfter))
	case left <= r.cfg.ExpiryWarning:
		r.log.Warn("smtpd: the TLS certificate expires soon",
			slog.Time("not_after", st.notAfter), slog.Int("days_left", int(left/(24*time.Hour))))
	}
}

// Start polls the files every Interval in a goroutine until ctx ends or Close
// is called. Calling it again does nothing.
func (r *CertReloader) Start(ctx context.Context) {
	r.startOnce.Do(func() {
		go func() {
			defer close(r.stopped)
			t := time.NewTicker(r.cfg.Interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					r.Check()
				case <-ctx.Done():
					return
				case <-r.stop:
					return
				}
			}
		}()
	})
}

// Close stops the polling goroutine and waits for it. The certificate in use
// keeps being served.
func (r *CertReloader) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	r.startOnce.Do(func() { close(r.stopped) }) // never started: nothing to wait for
	<-r.stopped
}
