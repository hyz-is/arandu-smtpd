package smtpd

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// model is the plain-minded reading of RFC 5321 section 4.5.2, applied to the
// bytes of a message: the message ends at the first "<CRLF>.<CRLF>" (a dot line
// at the very start counts), and a dot that begins a CRLF-delimited line is
// stuffing and is dropped. A line feed without a carriage return is not a line
// end. It returns the message and the number of input bytes it used, or -1 when
// the input has no end.
func model(in []byte) (msg []byte, used int) {
	var out []byte
	atBOL := true
	for i := 0; i < len(in); {
		if atBOL && in[i] == '.' {
			if i+2 < len(in) && in[i+1] == '\r' && in[i+2] == '\n' {
				return out, i + 3
			}
			if i+1 >= len(in) || (in[i+1] == '\r' && i+2 >= len(in)) {
				return out, -1
			}
			i++ // stuffing
			atBOL = false
			continue
		}
		atBOL = false
		out = append(out, in[i])
		if in[i] == '\n' && i > 0 && in[i-1] == '\r' {
			atBOL = true
		}
		i++
	}
	return out, -1
}

func readAllWith(d *dotReader, size int) ([]byte, error) {
	var out []byte
	buf := make([]byte, size)
	for {
		n, err := d.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func newDot(in []byte, bufSize int, max int64) (*dotReader, *bufio.Reader) {
	br := bufio.NewReaderSize(bytes.NewReader(in), bufSize)
	d := &dotReader{}
	d.reset(br, max, false)
	return d, br
}

func TestDotReaderMatchesTheModel(t *testing.T) {
	for _, tc := range []string{
		".\r\n",
		"hello\r\n.\r\n",
		"a\r\n..\r\n.\r\n",
		"a\r\n...x\r\n.\r\n",
		".hidden\r\n.\r\n",
		"a\r\n.\rb\r\n.\r\n",
		"no crlf end\r\n.\r\n",
		"bare\nlf\r\n.\r\n",
		"bare\n.\r\n.\r\n", // a "\n.\r\n" is not an end
		"bare\n.\nstill\r\n.\r\n",
		"\r\n\r\n.\r\n",
		"a\rb\r\n.\r\n",
		strings.Repeat("0123456789abcdef\r\n", 500) + ".\r\n",
		strings.Repeat(".dotted line\r\n", 300) + ".\r\n",
	} {
		want, used := model([]byte(tc))
		if used < 0 {
			t.Fatalf("the model found no end in %q", tc)
		}
		for _, bufSize := range []int{16, 17, 64, 4096} {
			for _, readSize := range []int{1, 2, 3, 7, 64, 100000} {
				trailer := "NOOP\r\n"
				d, br := newDot([]byte(tc+trailer), bufSize, 0)
				got, err := readAllWith(d, readSize)
				if err != nil {
					t.Fatalf("%q buf=%d read=%d: %v", tc, bufSize, readSize, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%q buf=%d read=%d:\n got %q\nwant %q", tc, bufSize, readSize, got, want)
				}
				rest, _ := io.ReadAll(br)
				if string(rest) != trailer {
					t.Fatalf("%q buf=%d read=%d: the reader left %q, want %q", tc, bufSize, readSize, rest, trailer)
				}
			}
		}
	}
}

func TestDotReaderReportsAMessageThatNeverEnds(t *testing.T) {
	d, _ := newDot([]byte("hello\r\nno end"), 16, 0)
	_, err := readAllWith(d, 4)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want ErrUnexpectedEOF", err)
	}
}

func TestDotReaderLimit(t *testing.T) {
	body := strings.Repeat("x", 98) + "\r\n" // 100 bytes
	for _, tc := range []struct {
		msg      string
		max      int64
		tooLarge bool
	}{
		{body + ".\r\n", 100, false},
		{body + ".\r\n", 99, true},
		{body + body + ".\r\n", 150, true},
		{body + body + ".\r\n", 200, false},
		{".\r\n", 1, false},
		{body + ".\r\n", 0, false},
	} {
		for _, readSize := range []int{1, 7, 50, 4096} {
			d, br := newDot([]byte(tc.msg+"NOOP\r\n"), 4096, tc.max)
			got, err := readAllWith(d, readSize)
			switch {
			case tc.tooLarge && (err != ErrDataTooLarge || !d.tooLarge):
				t.Fatalf("max=%d read=%d: got err=%v tooLarge=%v", tc.max, readSize, err, d.tooLarge)
			case !tc.tooLarge && err != nil:
				t.Fatalf("max=%d read=%d: %v", tc.max, readSize, err)
			case int64(len(got)) > tc.max && tc.max > 0:
				t.Fatalf("max=%d: delivered %d bytes", tc.max, len(got))
			}
			if err := d.drain(make([]byte, 64), 0); err != nil {
				t.Fatal(err)
			}
			if rest, _ := io.ReadAll(br); string(rest) != "NOOP\r\n" {
				t.Fatalf("max=%d read=%d: drain left %q", tc.max, readSize, rest)
			}
		}
	}
}

func TestDotReaderNoticesBareLineFeeds(t *testing.T) {
	d, _ := newDot([]byte("a\nb\r\n.\r\n"), 16, 0)
	readAllWith(d, 8)
	if !d.bareLF {
		t.Fatal("a bare LF went unnoticed")
	}
	d, _ = newDot([]byte("a\r\nb\r\n.\r\n"), 16, 0)
	readAllWith(d, 8)
	if d.bareLF {
		t.Fatal("a CRLF was taken for a bare LF")
	}
	// A CR and LF split across two reads are still a CRLF.
	d, _ = newDot([]byte("aaaaaaaaaaaaaaa\r\n.\r\n"), 16, 0)
	readAllWith(d, 1)
	if d.bareLF {
		t.Fatal("a CRLF split across reads was taken for a bare LF")
	}
}

func TestDotReaderRejectsBareLFWhenAsked(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("ok\r\nbad\nline\r\n.\r\n"))
	d := &dotReader{}
	d.reset(br, 0, true)
	_, err := readAllWith(d, 4096)
	if err != errBareLF {
		t.Fatalf("got %v, want errBareLF", err)
	}
}

func FuzzDotReader(f *testing.F) {
	for _, s := range []string{".\r\n", "a\r\n.\r\n", "a\r\n..\r\n.\r\n", "x\n.\r\n.\r\n", ".\rx\r\n.\r\n", "no end", "\r\n.\r"} {
		f.Add([]byte(s), uint8(3), uint8(0))
	}
	f.Fuzz(func(t *testing.T, in []byte, readSize, bufSel uint8) {
		bufSize := 16 + int(bufSel)%64
		rs := 1 + int(readSize)%40
		d, br := newDot(append(append([]byte(nil), in...), "\r\nQUIT\r\n"...), bufSize, 0)
		got, err := readAllWith(d, rs)

		// Whatever the input, the reader's output must agree with the model on
		// the same bytes (with the sentinel appended so there is a reader-visible
		// end only when the model also finds one).
		full := append(append([]byte(nil), in...), "\r\nQUIT\r\n"...)
		want, used := model(full)
		if used < 0 {
			if err == nil {
				t.Fatalf("the reader found an end in %q and the model did not", full)
			}
			return
		}
		if err != nil {
			t.Fatalf("the reader failed on %q: %v", full, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("input %q:\n got %q\nwant %q", full, got, want)
		}
		rest, _ := io.ReadAll(br)
		if !bytes.Equal(rest, full[used:]) {
			t.Fatalf("input %q: left %q, want %q", full, rest, full[used:])
		}
	})
}

func BenchmarkDotReader(b *testing.B) {
	line := strings.Repeat("x", 76) + "\r\n"
	msg := []byte(strings.Repeat(line, 1300) + ".\r\n") // about 100 KB
	buf := make([]byte, 32<<10)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	br := bufio.NewReaderSize(bytes.NewReader(msg), 8192)
	d := &dotReader{}
	for i := 0; i < b.N; i++ {
		br.Reset(bytes.NewReader(msg))
		d.reset(br, 0, false)
		for {
			_, err := d.Read(buf)
			if err != nil {
				break
			}
		}
	}
}

func BenchmarkSplitCommand(b *testing.B) {
	line := []byte("MAIL FROM:<sender@example.com> SIZE=1000 BODY=8BITMIME")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, arg := splitCommand(line)
		rest, _ := cutKeyword(arg, "FROM:")
		addr, params, _ := parsePath(rest)
		var mo MailOptions
		parseMailParams(params, &mo, caps{smtputf8: true, dsn: true})
		checkAddress(addr, true)
		_ = v
	}
}
