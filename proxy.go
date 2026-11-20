package smtpd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// proxyHeader is what a PROXY protocol header (HAProxy, versions 1 and 2) says
// about the connection it announces.
type proxyHeader struct {
	// Src and Dst are the original client and the address it connected to. They
	// are the zero value when the header carries no address (a version 2 LOCAL
	// command, or "PROXY UNKNOWN"), and then the addresses of the socket stand.
	Src, Dst netip.AddrPort
	// Local is true for a header that announces the proxy's own connection, as
	// a health check sends.
	Local bool
}

var errProxyHeader = errors.New("smtpd: malformed PROXY protocol header")

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyV1MaxLen = 107  // the longest line the version 1 specification allows
	proxyV2MaxLen = 1024 // addresses plus TLVs; the specification allows more, a server of ours does not need it
)

// readProxyHeader reads one PROXY protocol header from br. It consumes exactly
// the header, so whatever the client sent after it stays in br.
func readProxyHeader(br *bufio.Reader) (proxyHeader, error) {
	first, err := br.Peek(1)
	if err != nil {
		return proxyHeader{}, err
	}
	switch first[0] {
	case 'P':
		return readProxyV1(br)
	case '\r':
		return readProxyV2(br)
	}
	return proxyHeader{}, errProxyHeader
}

func readProxyV1(br *bufio.Reader) (proxyHeader, error) {
	var h proxyHeader
	// The line ends at the first LF; a header longer than the specification
	// allows never does within the limit.
	var buf [proxyV1MaxLen]byte
	n := 0
	for {
		c, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return h, err
		}
		if n == len(buf) {
			return h, errProxyHeader
		}
		buf[n] = c
		n++
		if c == '\n' {
			break
		}
	}
	line := buf[:n]
	if n < 2 || line[n-2] != '\r' {
		return h, errProxyHeader
	}
	line = line[:n-2]
	if !bytes.HasPrefix(line, []byte("PROXY ")) {
		return h, errProxyHeader
	}
	line = line[len("PROXY "):]
	if bytes.Equal(line, []byte("UNKNOWN")) || bytes.HasPrefix(line, []byte("UNKNOWN ")) {
		h.Local = true
		return h, nil
	}
	var fields [5][]byte
	for i := range fields {
		sp := bytes.IndexByte(line, ' ')
		switch {
		case sp < 0 && i == len(fields)-1:
			fields[i], line = line, nil
		case sp < 0 || sp == 0:
			return h, errProxyHeader
		default:
			fields[i], line = line[:sp], line[sp+1:]
		}
	}
	if len(line) != 0 {
		return h, errProxyHeader
	}
	want4 := string(fields[0]) == "TCP4"
	if !want4 && string(fields[0]) != "TCP6" {
		return h, errProxyHeader
	}
	src, err1 := netip.ParseAddr(string(fields[1]))
	dst, err2 := netip.ParseAddr(string(fields[2]))
	sp, err3 := strconv.ParseUint(string(fields[3]), 10, 16)
	dp, err4 := strconv.ParseUint(string(fields[4]), 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return h, errProxyHeader
	}
	if want4 != (src.Is4() && dst.Is4()) {
		return h, errProxyHeader
	}
	h.Src = netip.AddrPortFrom(src, uint16(sp))
	h.Dst = netip.AddrPortFrom(dst, uint16(dp))
	return h, nil
}

func readProxyV2(br *bufio.Reader) (proxyHeader, error) {
	var h proxyHeader
	var fixed [16]byte
	if _, err := io.ReadFull(br, fixed[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return h, err
	}
	if !bytes.Equal(fixed[:12], proxyV2Signature) || fixed[12]>>4 != 2 {
		return h, errProxyHeader
	}
	length := int(binary.BigEndian.Uint16(fixed[14:16]))
	if length > proxyV2MaxLen {
		return h, errProxyHeader
	}
	var body [proxyV2MaxLen]byte
	if _, err := io.ReadFull(br, body[:length]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return h, err
	}
	switch fixed[12] & 0x0F {
	case 0x0: // LOCAL
		h.Local = true
		return h, nil
	case 0x1: // PROXY
	default:
		return h, errProxyHeader
	}
	family, transport := fixed[13]>>4, fixed[13]&0x0F
	if transport != 1 && transport != 2 { // STREAM or DGRAM; anything else carries no address we can use
		h.Local = true
		return h, nil
	}
	switch family {
	case 1: // AF_INET
		if length < 12 {
			return h, errProxyHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:12]))
	case 2: // AF_INET6
		if length < 36 {
			return h, errProxyHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])), binary.BigEndian.Uint16(body[32:34]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])), binary.BigEndian.Uint16(body[34:36]))
	default: // AF_UNSPEC, AF_UNIX
		h.Local = true
	}
	return h, nil
}

// bufferedConn is a net.Conn that serves the bytes a bufio.Reader read ahead
// before it reads the connection itself. It is what the connection becomes when
// the client sent something after the PROXY header in the same packet, which a
// client that starts with a TLS handshake does.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }
