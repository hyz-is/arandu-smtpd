package unit_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hyz-is/arandu-smtpd"
)

// The benchmarks run the server and its clients in one process over loopback,
// so the numbers are a floor for the server (the clients take CPU the server
// would have) and they allocate nothing on the client side, so allocs/op is the
// server's.
//
//	go test -run '^$' -bench . -benchtime 3s ./tests/Unit

// sinkBackend accepts every message and throws it away.
type sinkBackend struct{}

func (sinkBackend) NewSession(*smtpd.Conn) (smtpd.Session, error) { return &sinkSession{}, nil }

type sinkSession struct{ smtpd.RefuseSession }

func (*sinkSession) Mail(string, *smtpd.MailOptions) error { return nil }
func (*sinkSession) Rcpt(string, *smtpd.RcptOptions) error { return nil }
func (*sinkSession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func benchServer(b *testing.B) string {
	srv := &smtpd.Server{
		Backend:             sinkBackend{},
		Hostname:            "bench.test",
		MaxConnections:      -1,
		MaxConnectionsPerIP: -1,
		MaxMessageBytes:     64 << 20,
		MaxErrors:           -1,
	}
	return start(b, srv, false)
}

// benchClient is a client that does not allocate while it runs.
type benchClient struct {
	c  net.Conn
	br *bufio.Reader
}

func newBenchClient(b *testing.B, addr string) *benchClient {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	return &benchClient{c: c, br: bufio.NewReaderSize(c, 4096)}
}

// replies reads n complete replies and fails unless each starts with want.
func (c *benchClient) replies(b *testing.B, n int, want byte) {
	for ; n > 0; n-- {
		for {
			line, err := c.br.ReadSlice('\n')
			if err != nil {
				b.Fatalf("reading a reply: %v", err)
			}
			if len(line) < 4 || line[0] != want {
				b.Fatalf("unexpected reply %q", line)
			}
			if line[3] == ' ' {
				break
			}
		}
	}
}

func (c *benchClient) write(b *testing.B, p []byte) {
	if _, err := c.c.Write(p); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkSessionsPerSecond(b *testing.B) {
	addr := benchServer(b)
	ehlo, quit := []byte("EHLO bench.client\r\n"), []byte("QUIT\r\n")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := newBenchClient(b, addr)
			c.replies(b, 1, '2') // greeting
			c.write(b, ehlo)
			c.replies(b, 1, '2')
			c.write(b, quit)
			c.replies(b, 1, '2')
			c.c.Close()
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "sessions/s")
}

func benchBody(size int) []byte {
	line := bytes.Repeat([]byte("x"), 76)
	line = append(line, '\r', '\n')
	var body bytes.Buffer
	body.WriteString("Subject: benchmark\r\nFrom: a@x.test\r\n\r\n")
	for body.Len() < size {
		body.Write(line)
	}
	return body.Bytes()
}

func benchMessages(b *testing.B, size int, mode string) {
	addr := benchServer(b)
	body := benchBody(size)
	envelope := []byte("MAIL FROM:<sender@example.com>\r\nRCPT TO:<rcpt@example.org>\r\n")

	// One write per message for the pipelined forms.
	var pipelined []byte
	var bdat []byte
	switch mode {
	case "pipelined":
		pipelined = append(pipelined, envelope...)
		pipelined = append(pipelined, "DATA\r\n"...)
		pipelined = append(pipelined, body...)
		pipelined = append(pipelined, ".\r\n"...)
	case "bdat":
		bdat = append(bdat, envelope...)
		bdat = append(bdat, "BDAT "+strconv.Itoa(len(body))+" LAST\r\n"...)
		bdat = append(bdat, body...)
	}
	trailer := []byte(".\r\n")

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := newBenchClient(b, addr)
		defer c.c.Close()
		c.replies(b, 1, '2')
		c.write(b, []byte("EHLO bench.client\r\n"))
		c.replies(b, 1, '2')
		for pb.Next() {
			switch mode {
			case "sequential":
				c.write(b, []byte("MAIL FROM:<sender@example.com>\r\n"))
				c.replies(b, 1, '2')
				c.write(b, []byte("RCPT TO:<rcpt@example.org>\r\n"))
				c.replies(b, 1, '2')
				c.write(b, []byte("DATA\r\n"))
				c.replies(b, 1, '3')
				c.write(b, body)
				c.write(b, trailer)
				c.replies(b, 1, '2')
			case "pipelined":
				c.write(b, pipelined)
				c.replies(b, 2, '2')
				c.replies(b, 1, '3')
				c.replies(b, 1, '2')
			case "bdat":
				c.write(b, bdat)
				c.replies(b, 3, '2')
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "messages/s")
}

func BenchmarkMessages(b *testing.B) {
	for _, size := range []int{1 << 10, 100 << 10, 1 << 20} {
		for _, mode := range []string{"sequential", "pipelined", "bdat"} {
			b.Run(fmt.Sprintf("%s/%s", byteSize(size), mode), func(b *testing.B) {
				benchMessages(b, size, mode)
			})
		}
	}
}

func byteSize(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%dMiB", n>>20)
	}
	return fmt.Sprintf("%dKiB", n>>10)
}

// BenchmarkOneConnectionOneMessageAtATime is the latency of a message on a
// single connection, with nothing else running: what one client sees.
func BenchmarkOneConnectionOneMessageAtATime(b *testing.B) {
	addr := benchServer(b)
	body := benchBody(1 << 10)
	pipelined := append([]byte("MAIL FROM:<s@example.com>\r\nRCPT TO:<r@example.org>\r\nDATA\r\n"), body...)
	pipelined = append(pipelined, ".\r\n"...)
	c := newBenchClient(b, addr)
	defer c.c.Close()
	c.replies(b, 1, '2')
	c.write(b, []byte("EHLO bench.client\r\n"))
	c.replies(b, 1, '2')
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.write(b, pipelined)
		c.replies(b, 2, '2')
		c.replies(b, 1, '3')
		c.replies(b, 1, '2')
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/1000, "µs/message")
	_ = time.Now
}
