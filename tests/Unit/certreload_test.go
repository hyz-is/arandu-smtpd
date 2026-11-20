package unit_test

import (
	"bufio"
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

func writePair(t *testing.T, dir string, serial int64) (certPath, keyPath string) {
	t.Helper()
	_, certPEM, keyPEM := testCert(t, serial)
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// servedSerial connects, starts TLS the way a client of a submission port does,
// and returns the serial number of the certificate it was shown.
func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	r := dial(t, addr)
	r.hello()
	r.expect("STARTTLS", "220 ")
	tc := tls.Client(r.conn, clientTLS())
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	return tc.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestTheServerServesARenewedCertificateWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, 1)
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	srv := newServer(&backend{})
	srv.TLSConfig = rl.TLSConfig()
	addr := start(t, srv, false)

	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("serial before renewal = %d", got)
	}
	if res, err := rl.Check(); res != smtpd.CertUnchanged || err != nil {
		t.Fatalf("Check with nothing new = %v, %v", res, err)
	}

	writePair(t, dir, 2)
	if res, err := rl.Check(); res != smtpd.CertReloaded || err != nil {
		t.Fatalf("Check after renewal = %v, %v", res, err)
	}
	if got := servedSerial(t, addr); got != 2 {
		t.Fatalf("serial after renewal = %d, want 2", got)
	}
}

func TestAHalfWrittenRenewalKeepsTheCertificateInUse(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, 1)
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	// Garbage in the certificate file.
	os.WriteFile(certPath, []byte("not a certificate"), 0o600)
	if res, err := rl.Check(); res != smtpd.CertFailed || err == nil {
		t.Fatalf("Check on garbage = %v, %v", res, err)
	}

	// A new certificate with the old key: a renewal caught between its two files.
	_, certPEM2, _ := testCert(t, 2)
	os.WriteFile(certPath, certPEM2, 0o600)
	if res, err := rl.Check(); res != smtpd.CertFailed || err == nil {
		t.Fatalf("Check on a mismatched pair = %v, %v", res, err)
	}

	// Missing files.
	os.Remove(keyPath)
	if res, _ := rl.Check(); res != smtpd.CertFailed {
		t.Fatalf("Check on a missing key = %v", res)
	}

	cert, err := rl.GetCertificate(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("the certificate in use changed: %v %v", cert, err)
	}
}

func TestACertificateRenewedByASymlinkSwapIsSeen(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []struct {
		name   string
		serial int64
	}{{"a", 1}, {"b", 2}} {
		sub := filepath.Join(dir, "archive-"+v.name)
		os.Mkdir(sub, 0o700)
		writePair(t, sub, v.serial)
	}
	live := filepath.Join(dir, "live")
	if err := os.Symlink(filepath.Join(dir, "archive-a"), live); err != nil {
		t.Skip("symlinks are not available:", err)
	}
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{
		CertFile: filepath.Join(live, "tls.crt"), KeyFile: filepath.Join(live, "tls.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	// What certbot does: point the link somewhere else.
	tmp := filepath.Join(dir, "live.new")
	os.Symlink(filepath.Join(dir, "archive-b"), tmp)
	if err := os.Rename(tmp, live); err != nil {
		t.Fatal(err)
	}
	if res, err := rl.Check(); res != smtpd.CertReloaded || err != nil {
		t.Fatalf("Check after the swap = %v, %v", res, err)
	}
	cert, _ := rl.GetCertificate(nil)
	if cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("serial = %d", cert.Leaf.SerialNumber.Int64())
	}
}

func TestStartPollsTheFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, 1)
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: certPath, KeyFile: keyPath, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rl.Start(t.Context())
	rl.Start(t.Context()) // a second call does nothing
	defer rl.Close()

	writePair(t, dir, 7)
	deadline := time.Now().Add(5 * time.Second)
	for {
		cert, _ := rl.GetCertificate(nil)
		if cert.Leaf.SerialNumber.Int64() == 7 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the poller did not pick up the new certificate")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCertReloaderRefusesBadInput(t *testing.T) {
	if _, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{}); err == nil {
		t.Error("no paths accepted")
	}
	dir := t.TempDir()
	if _, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: filepath.Join(dir, "x.crt"), KeyFile: filepath.Join(dir, "x.key")}); err == nil {
		t.Error("missing files accepted")
	}
	// Closing a reloader that was never started returns.
	certPath, keyPath := writePair(t, dir, 1)
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	rl.Close()
	rl.Close()
}

func TestTheReloaderWarnsBeforeTheCertificateExpires(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, 1)
	var buf lockedBuffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	rl, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{
		CertFile: certPath, KeyFile: keyPath, Logger: log,
		Now: func() time.Time { return time.Now().Add(85 * 24 * time.Hour) }, // five days before it expires
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	if !strings.Contains(buf.String(), "expires soon") {
		t.Fatalf("no warning in %q", buf.String())
	}
	if rl.NotAfter().IsZero() {
		t.Fatal("NotAfter is zero")
	}

	buf2 := lockedBuffer{}
	rl2, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{
		CertFile: certPath, KeyFile: keyPath, Logger: slog.New(slog.NewTextHandler(&buf2, nil)),
		Now: func() time.Time { return time.Now().Add(100 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl2.Close()
	if !strings.Contains(buf2.String(), "expired") {
		t.Fatalf("no expiry error in %q", buf2.String())
	}
}

func TestCertResultStrings(t *testing.T) {
	for r, want := range map[smtpd.CertResult]string{smtpd.CertUnchanged: "unchanged", smtpd.CertReloaded: "reloaded", smtpd.CertFailed: "failed"} {
		if r.String() != want {
			t.Errorf("%d = %q", r, r.String())
		}
	}
}

func TestTLSMinimumVersionIsRaisedToTLS12(t *testing.T) {
	pair, _, _ := testCert(t, 1)
	srv := newServer(&backend{})
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS10}
	addr := start(t, srv, true)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: v, MaxVersion: v})
		if err != nil {
			t.Fatalf("version %x: %v", v, err)
		}
		c.Close()
	}
	if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil {
		c.Close()
		t.Fatal("TLS 1.1 was accepted")
	}
}

func TestATLSHandshakeFailureIsCounted(t *testing.T) {
	srv := tlsServer(t, &backend{})
	addr := start(t, srv, true)
	r := dial(t, addr) // plaintext into a TLS port
	r.write("EHLO plain\r\n")
	r.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	bufio.NewReader(r.conn).ReadByte()
	waitFor(t, "the failure to be counted", func() bool { return srv.Stats().TLSFailures == 1 })
}
