package smtpd

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSplitCommand(t *testing.T) {
	for _, tc := range []struct {
		line string
		v    verb
		arg  string
	}{
		{"EHLO example.com", verbEHLO, "example.com"},
		{"ehlo   spaced   ", verbEHLO, "spaced"},
		{"Mail FROM:<a@b>", verbMAIL, "FROM:<a@b>"},
		{"rcpt to:<a@b>", verbRCPT, "to:<a@b>"},
		{"DATA", verbDATA, ""},
		{"BDAT 10 LAST", verbBDAT, "10 LAST"},
		{"RSET", verbRSET, ""},
		{"NOOP x", verbNOOP, "x"},
		{"QUIT", verbQUIT, ""},
		{"VRFY u", verbVRFY, "u"},
		{"EXPN l", verbEXPN, "l"},
		{"HELP", verbHELP, ""},
		{"STARTTLS", verbSTARTTLS, ""},
		{"starttls", verbSTARTTLS, ""},
		{"AUTH PLAIN abc", verbAUTH, "PLAIN abc"},
		{"STARTTLSX", verbUnknown, ""},
		{"HEL", verbUnknown, ""},
		{"", verbUnknown, ""},
		{"   ", verbUnknown, ""},
		{"VERYLONGVERB arg", verbUnknown, "arg"},
	} {
		v, arg := splitCommand([]byte(tc.line))
		if v != tc.v || string(arg) != tc.arg {
			t.Errorf("splitCommand(%q) = %d %q, want %d %q", tc.line, v, arg, tc.v, tc.arg)
		}
	}
}

func TestParsePath(t *testing.T) {
	for _, tc := range []struct {
		in, addr, params string
		ok               bool
	}{
		{"<a@b.test>", "a@b.test", "", true},
		{"<a@b.test> SIZE=10 BODY=8BITMIME", "a@b.test", "SIZE=10 BODY=8BITMIME", true},
		{"<>", "", "", true},
		{"<@r1,@r2:u@b.test>", "u@b.test", "", true},
		{`<"a>b"@x.test> SIZE=1`, `"a>b"@x.test`, "SIZE=1", true},
		{`<"a\"b"@x.test>`, `"a\"b"@x.test`, "", true},
		{"a@b.test", "a@b.test", "", true},
		{"a@b.test SIZE=1", "a@b.test", "SIZE=1", true},
		{"<a@b.test", "", "", false},
		{"<a@b.test>x", "", "", false},
		{"<@r1>", "", "", false},
		{"", "", "", false},
	} {
		addr, params, ok := parsePath([]byte(tc.in))
		if ok != tc.ok || string(addr) != tc.addr || string(params) != tc.params {
			t.Errorf("parsePath(%q) = %q %q %v, want %q %q %v", tc.in, addr, params, ok, tc.addr, tc.params, tc.ok)
		}
	}
}

func TestCheckAddress(t *testing.T) {
	long := strings.Repeat("a", 65)
	for _, tc := range []struct {
		addr       string
		allowEmpty bool
		ok         bool
		nonASCII   bool
	}{
		{"a@b.test", false, true, false},
		{"first.last+tag@sub.example.co", false, true, false},
		{"a@[192.0.2.1]", false, true, false},
		{`"quoted local"@b.test`, false, true, false},
		{`"a\"b"@b.test`, false, true, false},
		{"", true, true, false},
		{"", false, false, false},
		{"postmaster", false, true, false},
		{"POSTMASTER", false, true, false},
		{"postmaster", true, false, false},
		{"nodomain", false, false, false},
		{"@b.test", false, false, false},
		{"a@", false, false, false},
		{"a@b..test", false, false, false},
		{"a@.b.test", false, false, false},
		{"a@b.test.", false, false, false},
		{"a@-b.test", false, false, false},
		{"a b@c.test", false, false, false},
		{"a@b c.test", false, false, false},
		{"a<@c.test", false, false, false},
		{"a\x00@c.test", false, false, false},
		{`"unterminated@c.test`, false, false, false},
		{"\"\\\x0e\"@0", false, false, false}, // a quoted pair may not escape a control byte (found by the fuzzer)
		{long + "@c.test", false, false, false},
		{"hé@c.test", false, true, true},
		{"a@bé.test", false, true, true},
		{"日本@例.jp", false, true, true},
	} {
		ok, nonASCII := checkAddress([]byte(tc.addr), tc.allowEmpty)
		if ok != tc.ok || (ok && nonASCII != tc.nonASCII) {
			t.Errorf("checkAddress(%q, %v) = %v %v, want %v %v", tc.addr, tc.allowEmpty, ok, nonASCII, tc.ok, tc.nonASCII)
		}
	}
}

func TestXText(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		ok      bool
	}{
		{"plain", "plain", true},
		{"a+2Bb", "a+b", true},
		{"a+3Db", "a=b", true},
		{"+C3+A9", "é", true},
		{"", "", true},
		{"a+2", "", false},
		{"a+2b", "", false}, // lower-case hex is not xtext
		{"a+zz", "", false},
		{"a=b", "", false},
		{"a b", "", false},
		{"a\x7fb", "", false},
	} {
		got, ok := decodeXText([]byte(tc.in))
		if ok != tc.ok || (ok && got != tc.out) {
			t.Errorf("decodeXText(%q) = %q %v, want %q %v", tc.in, got, ok, tc.out, tc.ok)
		}
	}
}

func TestUXText(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		ok      bool
	}{
		{"plain", "plain", true},
		{`j\x{FC}lia`, "jülia", true},
		{`\x{1F600}`, "\U0001F600", true},
		{"jülia", "jülia", true},
		{`\x{D800}`, "", false},
		{`\x{110000}`, "", false},
		{`\x{}`, "", false},
		{`\x{ZZ}`, "", false},
		{`\x{41`, "", false},
		{`\q`, "", false},
		{"a=b", "", false},
	} {
		got, ok := decodeUXText([]byte(tc.in))
		if ok != tc.ok || (ok && got != tc.out) {
			t.Errorf("decodeUXText(%q) = %q %v, want %q %v", tc.in, got, ok, tc.out, tc.ok)
		}
	}
}

func TestParseBDAT(t *testing.T) {
	for _, tc := range []struct {
		in   string
		size int64
		last bool
		ok   bool
	}{
		{"10", 10, false, true},
		{"0 LAST", 0, true, true},
		{"1024 last", 1024, true, true},
		{"x", 0, false, false},
		{"", 0, false, false},
		{"10 FIRST", 0, false, false},
		{"-1", 0, false, false},
		{"1234567890123456789", 0, false, false},
	} {
		size, last, ok := parseBDAT([]byte(tc.in))
		if ok != tc.ok || (ok && (size != tc.size || last != tc.last)) {
			t.Errorf("parseBDAT(%q) = %d %v %v", tc.in, size, last, ok)
		}
	}
}

func TestAppendReply(t *testing.T) {
	for _, tc := range []struct {
		code int
		enh  string
		msg  string
		want string
	}{
		{250, "2.0.0", "Ok", "250 2.0.0 Ok\r\n"},
		{354, "", "Go", "354 Go\r\n"},
		{550, "5.7.1", "a\nb", "550-5.7.1 a\r\n550 5.7.1 b\r\n"},
		{550, "5.7.1", "bad\r\nsplit\r\n.", "550-5.7.1 bad\r\n550-5.7.1 split\r\n550 5.7.1 .\r\n"},
		{250, "", "", "250 \r\n"},
		{42, "", "x", "451 x\r\n"},
	} {
		if got := string(appendReply(nil, tc.code, tc.enh, tc.msg)); got != tc.want {
			t.Errorf("appendReply(%d,%q,%q) = %q, want %q", tc.code, tc.enh, tc.msg, got, tc.want)
		}
	}
}

func TestParsingDoesNotAllocate(t *testing.T) {
	line := []byte("MAIL FROM:<sender@example.com> SIZE=1000 BODY=8BITMIME RET=FULL")
	rcpt := []byte("TO:<rcpt@example.org> NOTIFY=SUCCESS,FAILURE")
	var mo MailOptions
	var ro RcptOptions
	var notify [4]DSNNotify
	caps := caps{smtputf8: true, dsn: true}
	allocs := testing.AllocsPerRun(100, func() {
		v, arg := splitCommand(line)
		if v != verbMAIL {
			t.Fatal("verb")
		}
		rest, _ := cutKeyword(arg, "FROM:")
		addr, params, _ := parsePath(rest)
		mo = MailOptions{}
		if e := parseMailParams(params, &mo, caps); e != nil {
			t.Fatal(e)
		}
		if ok, _ := checkAddress(addr, true); !ok {
			t.Fatal("address")
		}
		rest, _ = cutKeyword(rcpt, "TO:")
		addr, params, _ = parsePath(rest)
		ro = RcptOptions{Notify: notify[:0]}
		if e := parseRcptParams(params, &ro, caps); e != nil {
			t.Fatal(e)
		}
		if ok, _ := checkAddress(addr, false); !ok {
			t.Fatal("address")
		}
	})
	if allocs != 0 {
		t.Fatalf("parsing a MAIL and a RCPT allocates %v times, want 0", allocs)
	}
}

func FuzzSplitCommand(f *testing.F) {
	for _, s := range []string{"EHLO x", "MAIL FROM:<a@b>", "", " ", "STARTTLS", "AUTH PLAIN", "\x00", "A B C D E F G H I"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		v, arg := splitCommand(line)
		if v > verbAUTH {
			t.Fatalf("verb %d out of range", v)
		}
		if len(arg) > len(line) {
			t.Fatal("the argument is longer than the line")
		}
		if len(arg) > 0 && !bytes.Contains(line, arg) {
			t.Fatal("the argument is not a part of the line")
		}
		// A recognised verb is a verb whatever the case.
		if v != verbUnknown {
			up, down := splitUpper(line), splitLower(line)
			if v2, _ := splitCommand(up); v2 != v {
				t.Fatalf("upper-casing changed the verb: %d vs %d", v, v2)
			}
			if v2, _ := splitCommand(down); v2 != v {
				t.Fatalf("lower-casing changed the verb: %d vs %d", v, v2)
			}
		}
	})
}

func splitUpper(b []byte) []byte { return bytes.ToUpper(b) }
func splitLower(b []byte) []byte { return bytes.ToLower(b) }

func FuzzMailAndRcptArguments(f *testing.F) {
	for _, s := range []string{
		"FROM:<a@b.test> SIZE=10", "FROM:<>", "TO:<a@b.test> NOTIFY=NEVER ORCPT=rfc822;a+40b", "FROM:<@r:a@b>",
		`FROM:<"x y"@b.test> ENVID=a+2Bb`, "FROM: a@b", "TO:<", "FROM:<a@b> SMTPUTF8 BODY=8BITMIME RET=HDRS AUTH=<>",
		"TO:<a@b> ORCPT=utf-8;\\x{41}", "FROM:<a@b> =", "FROM:<a@b>  =  ", "\x00",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, arg []byte) {
		caps := caps{smtputf8: true, dsn: true}
		for _, kw := range []string{"FROM:", "TO:"} {
			rest, ok := cutKeyword(arg, kw)
			if !ok {
				continue
			}
			addr, params, ok := parsePath(rest)
			if !ok {
				continue
			}
			if len(addr) > len(rest) || len(params) > len(rest) {
				t.Fatal("a result is longer than the input")
			}
			valid, _ := checkAddress(addr, kw == "FROM:")
			if valid && len(addr) > maxAddress {
				t.Fatalf("accepted an address of %d bytes", len(addr))
			}
			var mo MailOptions
			var ro RcptOptions
			var buf [4]DSNNotify
			ro.Notify = buf[:0]
			if e := parseMailParams(params, &mo, caps); e == nil && mo.Size < 0 {
				t.Fatal("negative size")
			}
			parseRcptParams(params, &ro, caps)
			if len(ro.Notify) > 4 {
				t.Fatalf("%d notify values", len(ro.Notify))
			}
		}
	})
}

func FuzzXText(f *testing.F) {
	for _, s := range []string{"abc", "a+2Bb", "+", "+C3+A9", `\x{41}`, "a=b", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if s, ok := decodeXText(in); ok && len(s) > len(in) {
			t.Fatalf("xtext decoded %q to something longer: %q", in, s)
		}
		if s, ok := decodeUXText(in); ok && !utf8.ValidString(s) && utf8.Valid(in) {
			t.Fatalf("uxtext decoded valid UTF-8 %q to invalid %q", in, s)
		}
	})
}

func FuzzCheckAddress(f *testing.F) {
	for _, s := range []string{"a@b.test", `"a b"@c.test`, "a@[1.2.3.4]", "", "@", "a@", "\xff@b", `"\`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, addr []byte) {
		ok, _ := checkAddress(addr, true)
		if ok && len(addr) > 0 {
			for _, c := range addr {
				if c < 0x20 || c == 0x7f {
					t.Fatalf("accepted an address with the control byte %#x: %q", c, addr)
				}
				if c == ' ' && !bytes.Contains(addr, []byte{'"'}) {
					t.Fatalf("accepted an unquoted space: %q", addr)
				}
			}
			if bytes.IndexAny(addr, "<>") >= 0 && !bytes.Contains(addr, []byte{'"'}) {
				t.Fatalf("accepted an angle bracket outside quotes: %q", addr)
			}
		}
	})
}
