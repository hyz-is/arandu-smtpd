package smtpd

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// openBackend accepts everything. It is only for the fuzz test, which wants the
// whole dialogue to be reachable.
type openBackend struct{}

func (openBackend) NewSession(*Conn) (Session, error) { return &openSession{}, nil }

type openSession struct{ RefuseSession }

func (*openSession) Auth(string, string, string) error { return nil }
func (*openSession) Mail(string, *MailOptions) error   { return nil }
func (*openSession) Rcpt(string, *RcptOptions) error   { return nil }
func (*openSession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// converse runs one connection of the server against the bytes in, over an
// in-memory pipe, and fails if the server panics or does not finish.
func converse(t *testing.T, srv *Server, in []byte) {
	t.Helper()
	if err := srv.init(); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	srv.st.connsActive.add(1)
	srv.wg.Add(1)
	done := make(chan struct{})
	go func() {
		srv.handle(server, false)
		close(done)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(io.Discard, client)
	}()
	client.SetWriteDeadline(time.Now().Add(3 * time.Second))
	client.Write(in)
	// Let the server answer what it was sent, then hang up from the client.
	time.Sleep(time.Millisecond)
	client.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the server did not finish a conversation of %d bytes: %q", len(in), in)
	}
	wg.Wait()
	if p := srv.st.panics.load(); p != 0 {
		t.Fatalf("the server panicked on %q", in)
	}
}

func fuzzServer() *Server {
	return &Server{
		Backend:             openBackend{},
		AllowInsecureAuth:   true,
		MaxConnectionsPerIP: -1,
		AuthFailureDelay:    -1,
		CommandTimeout:      500 * time.Millisecond,
		DataTimeout:         500 * time.Millisecond,
		MaxMessageBytes:     4096,
		MaxLineLength:       600,
	}
}

func TestConversationSeeds(t *testing.T) {
	for _, in := range []string{
		"EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
		"EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nBDAT 5\r\nhelloBDAT 0 LAST\r\nQUIT\r\n",
		"EHLO x\r\nAUTH PLAIN AGEAYg==\r\nAUTH LOGIN\r\nYQ==\r\nYg==\r\nQUIT\r\n",
		"EHLO x\r\nAUTH PLAIN\r\n*\r\nMAIL FROM:<a@b.test> SIZE=99999\r\n",
		"\x00\x01\x02\r\n\r\n\r\nSTARTTLS\r\nDATA\r\n",
		"EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nBDAT 99999999999\r\nBDAT x\r\n",
	} {
		converse(t, fuzzServer(), []byte(in))
	}
}

func FuzzConversation(f *testing.F) {
	for _, in := range []string{
		"EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n",
		"EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nBDAT 5\r\nhelloBDAT 0 LAST\r\n",
		"EHLO x\r\nAUTH PLAIN AGEAYg==\r\nAUTH LOGIN\r\nYQ==\r\nYg==\r\n",
		"STARTTLS\r\nRSET\r\nNOOP\r\nVRFY a\r\nHELP\r\nEXPN x\r\n",
	} {
		f.Add([]byte(in))
	}
	srv := fuzzServer()
	f.Fuzz(func(t *testing.T, in []byte) {
		converse(t, srv, in)
	})
}

// The two benchmarks below isolate what the server itself allocates for a
// session: both make a pipe and a goroutine and move the same bytes, and only
// the second has the server on the other end. The difference is the server's.

var pipeScript = []byte("EHLO bench.client\r\nQUIT\r\n")

func BenchmarkPipeBaseline(b *testing.B) {
	b.ReportAllocs()
	buf := make([]byte, 4096)
	for i := 0; i < b.N; i++ {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			server.Read(buf[:1])
			server.Write([]byte("220 bench.test ESMTP ready\r\n"))
			server.Close()
			close(done)
		}()
		client.Write(pipeScript[:1])
		client.Read(buf)
		client.Close()
		<-done
	}
}

func BenchmarkPipeSession(b *testing.B) {
	srv := &Server{Backend: openBackend{}, Hostname: "bench.test", MaxConnectionsPerIP: -1, MaxConnections: -1}
	if err := srv.init(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	buf := make([]byte, 4096)
	for i := 0; i < b.N; i++ {
		client, server := net.Pipe()
		srv.st.connsActive.add(1)
		srv.wg.Add(1)
		done := make(chan struct{})
		go func() {
			srv.handle(server, false)
			close(done)
		}()
		client.Read(buf) // greeting
		client.Write(pipeScript[:19])
		client.Read(buf) // EHLO reply
		client.Write(pipeScript[19:])
		client.Read(buf) // 221
		client.Close()
		<-done
	}
}
