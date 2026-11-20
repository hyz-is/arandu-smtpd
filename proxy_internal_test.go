package smtpd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
)

func TestReadProxyHeaderV1(t *testing.T) {
	for _, tc := range []struct {
		in    string
		src   string
		dst   string
		local bool
		ok    bool
	}{
		{"PROXY TCP4 192.0.2.1 198.51.100.1 5000 25\r\nEHLO", "192.0.2.1:5000", "198.51.100.1:25", false, true},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 5000 25\r\n", "[2001:db8::1]:5000", "[2001:db8::2]:25", false, true},
		{"PROXY UNKNOWN\r\n", "", "", true, true},
		{"PROXY UNKNOWN 1 2 3 4\r\n", "", "", true, true},
		{"PROXY TCP4 192.0.2.1 198.51.100.1 5000 25\n", "", "", false, false},
		{"PROXY TCP4 192.0.2.1 198.51.100.1 5000\r\n", "", "", false, false},
		{"PROXY TCP4 192.0.2.1 198.51.100.1 5000 25 extra\r\n", "", "", false, false},
		{"PROXY TCP4 2001:db8::1 198.51.100.1 5000 25\r\n", "", "", false, false},
		{"PROXY TCP4 192.0.2.1 198.51.100.1 70000 25\r\n", "", "", false, false},
		{"PROXY UDP4 192.0.2.1 198.51.100.1 1 2\r\n", "", "", false, false},
		{"GET / HTTP/1.1\r\n", "", "", false, false},
		{"PROXY TCP4 1.1.1.1 2.2.2.2 1 2", "", "", false, false},
	} {
		h, err := readProxyHeader(bufio.NewReader(bytes.NewReader([]byte(tc.in))))
		if (err == nil) != tc.ok {
			t.Errorf("%q: err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if h.Local != tc.local || (tc.src != "" && (h.Src.String() != tc.src || h.Dst.String() != tc.dst)) {
			t.Errorf("%q: got %+v", tc.in, h)
		}
	}
}

func v2(cmd, fam byte, body []byte) []byte {
	out := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x20|cmd, fam)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

func TestReadProxyHeaderV2(t *testing.T) {
	v4 := append(netip.MustParseAddr("192.0.2.9").AsSlice(), netip.MustParseAddr("198.51.100.1").AsSlice()...)
	v4 = binary.BigEndian.AppendUint16(v4, 4242)
	v4 = binary.BigEndian.AppendUint16(v4, 25)
	a6, b6 := netip.MustParseAddr("2001:db8::9").As16(), netip.MustParseAddr("2001:db8::1").As16()
	v6 := append(a6[:], b6[:]...)
	v6 = binary.BigEndian.AppendUint16(v6, 4343)
	v6 = binary.BigEndian.AppendUint16(v6, 465)

	for _, tc := range []struct {
		name  string
		in    []byte
		src   string
		local bool
		ok    bool
	}{
		{"ipv4", v2(1, 0x11, v4), "192.0.2.9:4242", false, true},
		{"ipv4 with a TLV", v2(1, 0x11, append(append([]byte(nil), v4...), 0x04, 0, 2, 'h', 'i')), "192.0.2.9:4242", false, true},
		{"ipv6", v2(1, 0x21, v6), "[2001:db8::9]:4343", false, true},
		{"local", v2(0, 0x00, nil), "", true, true},
		{"unspec", v2(1, 0x00, nil), "", true, true},
		{"unix", v2(1, 0x31, make([]byte, 216)), "", true, true},
		{"short ipv4", v2(1, 0x11, v4[:8]), "", false, false},
		{"short ipv6", v2(1, 0x21, v6[:20]), "", false, false},
		{"bad version", append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x11, 0x11, 0, 0), "", false, false},
		{"bad command", v2(5, 0x11, v4), "", false, false},
		{"bad signature", append([]byte("\r\n\r\n\x00\r\nQUIX\n"), 0x21, 0x11, 0, 0), "", false, false},
		{"truncated", v2(1, 0x11, v4)[:20], "", false, false},
		{"too long", v2(1, 0x11, make([]byte, 2000)), "", false, false},
	} {
		h, err := readProxyHeader(bufio.NewReader(bytes.NewReader(tc.in)))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
			continue
		}
		if tc.ok && (h.Local != tc.local || (tc.src != "" && h.Src.String() != tc.src)) {
			t.Errorf("%s: got %+v", tc.name, h)
		}
	}
}

func TestProxyHeaderLeavesTheRestOfTheStream(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 192.0.2.1 198.51.100.1 5000 25\r\nEHLO x\r\n")))
	if _, err := readProxyHeader(br); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "EHLO x\r\n" {
		t.Fatalf("left %q", rest)
	}
}

func FuzzProxyHeader(f *testing.F) {
	f.Add([]byte("PROXY TCP4 192.0.2.1 198.51.100.1 5000 25\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(v2(1, 0x11, make([]byte, 12)))
	f.Add(v2(0, 0, nil))
	f.Add([]byte("\r\n\r\n\x00\r\nQUIT\n"))
	f.Add([]byte("PROXY "))
	f.Fuzz(func(t *testing.T, in []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(append(append([]byte(nil), in...), "TAIL"...)), 16)
		h, err := readProxyHeader(br)
		if err != nil {
			return
		}
		if h.Src.IsValid() != h.Dst.IsValid() {
			t.Fatalf("one address without the other: %+v", h)
		}
		if h.Local && h.Src.IsValid() {
			t.Fatalf("a local header with an address: %+v", h)
		}
		// A header is bounded: it never takes more than its fixed part and the
		// length it declares (at most proxyV2MaxLen).
		rest, _ := io.ReadAll(br)
		if consumed := len(in) + 4 - len(rest); consumed > 16+proxyV2MaxLen {
			t.Fatalf("the header consumed %d bytes", consumed)
		}
	})
}
