package smtpd

import (
	"bufio"
	"bytes"
	"io"
)

// States of the dot reader, which follows the line structure of the message
// across the boundaries of the reads it is given.
const (
	stBOL    uint8 = iota // at the start of a line
	stMid                 // inside a line
	stCR                  // inside a line, the last byte was CR
	stDot                 // read "." at the start of a line
	stDotCR               // read ".\r" at the start of a line
	stDone                // read the terminating "<CRLF>.<CRLF>"
	stFailed              // the connection failed before the terminator
)

// dotReader reads the message of a DATA command from the connection. It
// removes the dot-stuffing of RFC 5321 section 4.5.2 and ends at the line that
// holds a single dot, delivering the message with its CRLF line endings.
//
// The end of the message is "<CRLF>.<CRLF>" and nothing else. A bare LF
// followed by a dot is data, because accepting it as an end is how a message is
// smuggled past a server that does not (and is what SMTP smuggling is).
//
// It copies a line at a time with bytes.IndexByte and looks at single bytes
// only at the start of a line, so the cost per byte of a message is that of a
// copy.
type dotReader struct {
	br         *bufio.Reader
	st         uint8
	n          int64 // bytes delivered
	max        int64 // 0 means no limit
	err        error // sticky error returned by Read
	tooLarge   bool
	bareLF     bool
	connErr    error // a failure of the connection, as opposed to the end of the message
	bareCount  int
	rejectBare bool // Read fails as soon as a bare line feed is seen
}

func (d *dotReader) reset(br *bufio.Reader, max int64, rejectBare bool) {
	*d = dotReader{br: br, max: max, rejectBare: rejectBare}
}

// Read implements io.Reader.
func (d *dotReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	want := len(p)
	if d.max > 0 {
		// Room for one byte past the limit, which is how a message that is
		// exactly at the limit is told apart from one that is over it.
		if room := d.max - d.n + 1; int64(want) > room {
			want = int(room)
		}
	}
	n := 0
	for n < want {
		if d.br.Buffered() == 0 {
			if n > 0 {
				break
			}
			if _, err := d.br.Peek(1); err != nil {
				return 0, d.fail(err)
			}
		}
		buf, _ := d.br.Peek(d.br.Buffered())
		read, wrote := d.step(buf, p[n:want])
		d.br.Discard(read)
		n += wrote
		if d.st == stDone {
			break
		}
	}
	if d.rejectBare && d.bareLF {
		// What was copied holds the bad line: none of it is given to the reader.
		d.err = errBareLF
		return 0, d.err
	}
	d.n += int64(n)
	if d.max > 0 && d.n > d.max {
		d.tooLarge = true
		d.err = ErrDataTooLarge
		n -= int(d.n - d.max)
		d.n = d.max
		if n < 0 {
			n = 0
		}
		return n, nil
	}
	if d.st == stDone {
		d.err = io.EOF
		if n == 0 {
			return 0, io.EOF
		}
	}
	return n, nil
}

func (d *dotReader) fail(err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	d.st = stFailed
	d.connErr = err
	d.err = err
	return err
}

// step consumes bytes from src and writes the message bytes they stand for to
// dst, until src or dst runs out or the message ends. It reports how much of
// each it used.
func (d *dotReader) step(src, dst []byte) (read, wrote int) {
	i, o := 0, 0
	for i < len(src) && o < len(dst) {
		switch d.st {
		case stBOL:
			if src[i] == '.' {
				d.st = stDot
				i++
				continue
			}
			d.st = stMid
		case stDot:
			switch src[i] {
			case '\r':
				d.st = stDotCR
				i++
			case '\n':
				// ".<LF>" is not the terminator. The dot is stuffing, and the line
				// feed is a bare one.
				d.bareLF = true
				d.bareCount++
				dst[o] = '\n'
				o++
				i++
				d.st = stMid
			default:
				// Dot-stuffing: the first dot is dropped, and the byte after it
				// (which may be another dot) is data.
				d.st = stMid
			}
		case stDotCR:
			if src[i] == '\n' {
				i++
				d.st = stDone
				return i, o
			}
			// ".\rX": the dot is dropped and the CR is data.
			dst[o] = '\r'
			o++
			d.st = stCR
		default: // stMid, stCR
			chunk := src[i:]
			if room := len(dst) - o; len(chunk) > room {
				chunk = chunk[:room]
			}
			lf := bytes.IndexByte(chunk, '\n')
			if lf < 0 {
				copy(dst[o:], chunk)
				o += len(chunk)
				i += len(chunk)
				d.st = stMid
				if chunk[len(chunk)-1] == '\r' {
					d.st = stCR
				}
				continue
			}
			bare := !(lf > 0 && chunk[lf-1] == '\r') && !(lf == 0 && d.st == stCR)
			copy(dst[o:], chunk[:lf+1])
			o += lf + 1
			i += lf + 1
			if bare {
				// A line feed with no carriage return before it is not the end of a
				// line, so what follows is not the start of one: no dot after it is
				// stuffing and none of it can end the message.
				d.bareLF = true
				d.bareCount++
				d.st = stMid
			} else {
				d.st = stBOL
			}
		}
	}
	return i, o
}

// drain reads and throws away the rest of the message, so the connection is at
// the next command. It gives up, and reports why, when the connection fails or
// when more than limit bytes arrive after the point it started.
func (d *dotReader) drain(scratch []byte, limit int64) error {
	if d.st == stDone {
		return nil
	}
	if d.connErr != nil {
		return d.connErr
	}
	var total int64
	for d.st != stDone {
		if d.br.Buffered() == 0 {
			if _, err := d.br.Peek(1); err != nil {
				return d.fail(err)
			}
		}
		buf, _ := d.br.Peek(d.br.Buffered())
		read, _ := d.step(buf, scratch)
		d.br.Discard(read)
		total += int64(read)
		if limit > 0 && total > limit {
			return errDrainLimit
		}
	}
	return nil
}

type drainLimitError struct{}

func (drainLimitError) Error() string { return "smtpd: the client kept sending after the size limit" }

var errDrainLimit error = drainLimitError{}
