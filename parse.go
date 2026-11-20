package smtpd

import "bytes"

// verb is an SMTP command word.
type verb uint8

const (
	verbUnknown verb = iota
	verbHELO
	verbEHLO
	verbMAIL
	verbRCPT
	verbDATA
	verbBDAT
	verbRSET
	verbNOOP
	verbQUIT
	verbVRFY
	verbEXPN
	verbHELP
	verbSTARTTLS
	verbAUTH
)

// hasControl reports whether b holds a byte that cannot appear in a command
// line: a control character. A lone CR in the middle of a line is the one that
// matters, because a server and a proxy that disagree about it are how a
// command is smuggled past a filter.
func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// splitCommand reads the verb of a command line, without its line ending, and
// returns the argument that follows it. It does not allocate.
func splitCommand(line []byte) (verb, []byte) {
	line = bytes.TrimRight(line, " ")
	i := bytes.IndexByte(line, ' ')
	word, arg := line, []byte(nil)
	if i >= 0 {
		word = line[:i]
		arg = bytes.TrimLeft(line[i:], " ")
	}
	if len(word) == 0 || len(word) > 8 {
		return verbUnknown, arg
	}
	var up [8]byte
	for k, c := range word {
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		up[k] = c
	}
	switch string(up[:len(word)]) {
	case "HELO":
		return verbHELO, arg
	case "EHLO":
		return verbEHLO, arg
	case "MAIL":
		return verbMAIL, arg
	case "RCPT":
		return verbRCPT, arg
	case "DATA":
		return verbDATA, arg
	case "BDAT":
		return verbBDAT, arg
	case "RSET":
		return verbRSET, arg
	case "NOOP":
		return verbNOOP, arg
	case "QUIT":
		return verbQUIT, arg
	case "VRFY":
		return verbVRFY, arg
	case "EXPN":
		return verbEXPN, arg
	case "HELP":
		return verbHELP, arg
	case "STARTTLS":
		return verbSTARTTLS, arg
	case "AUTH":
		return verbAUTH, arg
	}
	return verbUnknown, arg
}

// eqFold reports whether b equals the upper-case ASCII word s, ignoring the
// case of b.
func eqFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != s[i] {
			return false
		}
	}
	return true
}

// cutKeyword removes a leading "FROM:" or "TO:" (any case) and the spaces
// after the colon, which some clients send although RFC 5321 does not allow
// them.
func cutKeyword(arg []byte, keyword string) ([]byte, bool) {
	if len(arg) < len(keyword) || !eqFold(arg[:len(keyword)], keyword) {
		return nil, false
	}
	return bytes.TrimLeft(arg[len(keyword):], " "), true
}

// parsePath reads the path that follows MAIL FROM: or RCPT TO: and returns its
// address, with any obsolete source route removed, and the parameters that
// follow it. A path without angle brackets is accepted as far as the first
// space, because old clients send it. The address is not validated here.
func parsePath(arg []byte) (addr, params []byte, ok bool) {
	if len(arg) == 0 {
		return nil, nil, false
	}
	if arg[0] != '<' {
		end := bytes.IndexByte(arg, ' ')
		if end < 0 {
			end = len(arg)
		}
		return arg[:end], bytes.TrimLeft(arg[end:], " "), end > 0
	}
	inQuote := false
	end := -1
scan:
	for i := 1; i < len(arg); i++ {
		switch c := arg[i]; {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == '>':
			end = i
			break scan
		}
	}
	if end < 0 {
		return nil, nil, false
	}
	addr = arg[1:end]
	rest := arg[end+1:]
	if len(rest) > 0 && rest[0] != ' ' {
		return nil, nil, false
	}
	// <@relay1,@relay2:user@host>: RFC 5321 says to ignore the route.
	if len(addr) > 0 && addr[0] == '@' {
		colon := bytes.IndexByte(addr, ':')
		if colon < 0 {
			return nil, nil, false
		}
		addr = addr[colon+1:]
	}
	return addr, bytes.TrimLeft(rest, " "), true
}

const (
	maxLocalPart = 64
	maxDomain    = 255
	maxAddress   = 254
)

// atext reports whether c can appear unquoted in the local part of an address.
func atext(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~', '.':
		return true
	}
	return false
}

// checkAddress validates the address of a path. An empty address is allowed
// only when allowEmpty is set (the null reverse-path). "postmaster" without a
// domain is allowed for a recipient. Non-ASCII bytes are reported through
// nonASCII so the caller can require SMTPUTF8; they are otherwise accepted as
// letters of the local part and the domain.
func checkAddress(addr []byte, allowEmpty bool) (ok, nonASCII bool) {
	if len(addr) == 0 {
		return allowEmpty, false
	}
	if len(addr) > maxAddress {
		return false, false
	}
	at := lastUnquotedAt(addr)
	if at < 0 {
		return !allowEmpty && eqFold(addr, "POSTMASTER"), false
	}
	local, domain := addr[:at], addr[at+1:]
	if len(local) == 0 || len(local) > maxLocalPart || len(domain) == 0 || len(domain) > maxDomain {
		return false, false
	}
	if local[0] == '"' {
		if !validQuoted(local, &nonASCII) {
			return false, false
		}
	} else {
		for _, c := range local {
			switch {
			case c >= 0x80:
				nonASCII = true
			case !atext(c):
				return false, false
			}
		}
	}
	if domain[0] == '[' {
		return domain[len(domain)-1] == ']' && validLiteral(domain[1:len(domain)-1]), nonASCII
	}
	prev := byte('.')
	for _, c := range domain {
		switch {
		case c >= 0x80:
			nonASCII = true
		case c == '.':
			if prev == '.' {
				return false, false
			}
		case c == '-', '0' <= c && c <= '9', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		default:
			return false, false
		}
		prev = c
	}
	return prev != '.' && domain[0] != '-', nonASCII
}

func lastUnquotedAt(addr []byte) int {
	if len(addr) > 0 && addr[0] == '"' {
		for i := 1; i < len(addr); i++ {
			switch addr[i] {
			case '\\':
				i++
			case '"':
				if i+1 < len(addr) && addr[i+1] == '@' {
					return i + 1
				}
				return -1
			}
		}
		return -1
	}
	return bytes.LastIndexByte(addr, '@')
}

func validQuoted(q []byte, nonASCII *bool) bool {
	if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
		return false
	}
	for i := 1; i < len(q)-1; i++ {
		c := q[i]
		switch {
		case c == '\\':
			i++
			if i >= len(q)-1 {
				return false
			}
			// A quoted pair escapes a printable character, not a control one.
			if e := q[i]; e < 0x20 || e == 0x7f {
				return false
			}
			if q[i] >= 0x80 {
				*nonASCII = true
			}
		case c == '"':
			return false
		case c >= 0x80:
			*nonASCII = true
		case c < 0x20 || c == 0x7f:
			return false
		}
	}
	return true
}

func validLiteral(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

// nextParam returns the next KEY or KEY=VALUE word of a parameter list.
func nextParam(params []byte) (key, val, rest []byte, hasVal bool) {
	params = bytes.TrimLeft(params, " ")
	end := bytes.IndexByte(params, ' ')
	if end < 0 {
		end = len(params)
	}
	word := params[:end]
	rest = params[end:]
	if eq := bytes.IndexByte(word, '='); eq >= 0 {
		return word[:eq], word[eq+1:], rest, true
	}
	return word, nil, rest, false
}

// parseUint reads a decimal number of at most 18 digits.
func parseUint(b []byte) (int64, bool) {
	if len(b) == 0 || len(b) > 18 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeXText decodes the xtext encoding of RFC 3461: "+" and two upper-case
// hex digits stand for a byte, and every other byte is a printable ASCII
// character other than "+" and "=".
func decodeXText(s []byte) (string, bool) {
	var small [64]byte
	out := small[:0]
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			out = append(out, hi<<4|lo)
			i += 2
		case c < 0x21 || c > 0x7e || c == '=':
			return "", false
		default:
			out = append(out, c)
		}
	}
	return string(out), true
}

// decodeUXText decodes the uxtext encoding of RFC 6533, which is xtext with
// UTF-8 allowed and "\x{HEX}" in place of "+HH".
func decodeUXText(s []byte) (string, bool) {
	var small [64]byte
	out := small[:0]
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+3 >= len(s) || s[i+1] != 'x' || s[i+2] != '{' {
				return "", false
			}
			end := bytes.IndexByte(s[i+3:], '}')
			if end < 1 || end > 6 {
				return "", false
			}
			var r rune
			for _, h := range s[i+3 : i+3+end] {
				v, ok := hexVal(h)
				if !ok {
					return "", false
				}
				r = r<<4 | rune(v)
			}
			if r > 0x10FFFF || (0xD800 <= r && r <= 0xDFFF) {
				return "", false
			}
			out = appendRune(out, r)
			i += 3 + end
		case c < 0x21 || c == 0x7f || c == '=':
			return "", false
		default:
			out = append(out, c)
		}
	}
	return string(out), true
}

func appendRune(b []byte, r rune) []byte {
	switch {
	case r < 0x80:
		return append(b, byte(r))
	case r < 0x800:
		return append(b, 0xC0|byte(r>>6), 0x80|byte(r)&0x3F)
	case r < 0x10000:
		return append(b, 0xE0|byte(r>>12), 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F)
	}
	return append(b, 0xF0|byte(r>>18), 0x80|byte(r>>12)&0x3F, 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F)
}

// parseMailParams reads the parameters of MAIL FROM into opts, which the caller
// has reset. A syntax error is a 501; a parameter that is well formed but not
// offered is a 555.
func parseMailParams(params []byte, opts *MailOptions, caps caps) *Error {
	var seen uint8
	for len(bytes.TrimLeft(params, " ")) > 0 {
		key, val, rest, hasVal := nextParam(params)
		params = rest
		var bit uint8
		switch {
		case eqFold(key, "SIZE"):
			bit = 1
			if !hasVal {
				return errSyntaxArgs
			}
			n, ok := parseUint(val)
			if !ok {
				return errSyntaxArgs
			}
			opts.Size = n
		case eqFold(key, "BODY"):
			bit = 2
			switch {
			case !hasVal:
				return errSyntaxArgs
			case eqFold(val, "7BIT"):
				opts.Body = Body7Bit
			case eqFold(val, "8BITMIME"):
				opts.Body = Body8BitMIME
			default:
				return errParamNotSupp
			}
		case eqFold(key, "SMTPUTF8"):
			bit = 4
			if hasVal {
				return errSyntaxArgs
			}
			if !caps.smtputf8 {
				return errParamNotSupp
			}
			opts.UTF8 = true
		case eqFold(key, "RET"):
			bit = 8
			if !caps.dsn {
				return errParamNotSupp
			}
			switch {
			case !hasVal:
				return errSyntaxArgs
			case eqFold(val, "FULL"):
				opts.Return = ReturnFull
			case eqFold(val, "HDRS"):
				opts.Return = ReturnHeaders
			default:
				return errSyntaxArgs
			}
		case eqFold(key, "ENVID"):
			bit = 16
			if !caps.dsn {
				return errParamNotSupp
			}
			if !hasVal || len(val) == 0 || len(val) > 100 {
				return errSyntaxArgs
			}
			s, ok := decodeXText(val)
			if !ok {
				return errSyntaxArgs
			}
			opts.EnvelopeID = s
		case eqFold(key, "AUTH"):
			bit = 32
			if !hasVal || len(val) == 0 {
				return errSyntaxArgs
			}
			if string(val) == "<>" {
				opts.Auth = ""
				break
			}
			s, ok := decodeXText(val)
			if !ok {
				return errSyntaxArgs
			}
			opts.Auth = s
		default:
			return errParamNotSupp
		}
		if seen&bit != 0 {
			return errSyntaxArgs
		}
		seen |= bit
	}
	return nil
}

// parseRcptParams reads the parameters of RCPT TO into opts, whose Notify slice
// has its backing array supplied by the caller so a recipient costs no
// allocation.
func parseRcptParams(params []byte, opts *RcptOptions, caps caps) *Error {
	var seen uint8
	for len(bytes.TrimLeft(params, " ")) > 0 {
		key, val, rest, hasVal := nextParam(params)
		params = rest
		var bit uint8
		switch {
		case eqFold(key, "NOTIFY"):
			bit = 1
			if !caps.dsn {
				return errParamNotSupp
			}
			if !hasVal || len(val) == 0 {
				return errSyntaxArgs
			}
			if e := parseNotify(val, opts); e != nil {
				return e
			}
		case eqFold(key, "ORCPT"):
			bit = 2
			if !caps.dsn {
				return errParamNotSupp
			}
			semi := bytes.IndexByte(val, ';')
			if !hasVal || semi < 1 || semi == len(val)-1 || len(val) > 500 {
				return errSyntaxArgs
			}
			typ, enc := val[:semi], val[semi+1:]
			for _, c := range typ {
				if !(c == '-' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
					return errSyntaxArgs
				}
			}
			var s string
			var ok bool
			if eqFold(typ, "UTF-8") {
				s, ok = decodeUXText(enc)
			} else {
				s, ok = decodeXText(enc)
			}
			if !ok {
				return errSyntaxArgs
			}
			opts.OriginalRecipientType = string(typ)
			opts.OriginalRecipient = s
		default:
			return errParamNotSupp
		}
		if seen&bit != 0 {
			return errSyntaxArgs
		}
		seen |= bit
	}
	return nil
}

func parseNotify(val []byte, opts *RcptOptions) *Error {
	var seen uint8
	for len(val) > 0 {
		item := val
		if comma := bytes.IndexByte(val, ','); comma >= 0 {
			item, val = val[:comma], val[comma+1:]
			if len(val) == 0 {
				return errSyntaxArgs
			}
		} else {
			val = nil
		}
		var n DSNNotify
		var bit uint8
		switch {
		case eqFold(item, "NEVER"):
			n, bit = NotifyNever, 1
		case eqFold(item, "SUCCESS"):
			n, bit = NotifySuccess, 2
		case eqFold(item, "FAILURE"):
			n, bit = NotifyFailure, 4
		case eqFold(item, "DELAY"):
			n, bit = NotifyDelay, 8
		default:
			return errSyntaxArgs
		}
		if seen&bit != 0 {
			return errSyntaxArgs
		}
		seen |= bit
		opts.Notify = append(opts.Notify, n)
	}
	if seen&1 != 0 && seen != 1 {
		return errSyntaxArgs
	}
	return nil
}

// caps are the optional extensions a server offers, as the parser needs them.
type caps struct {
	smtputf8 bool
	dsn      bool
}
