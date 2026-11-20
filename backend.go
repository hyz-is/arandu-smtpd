package smtpd

import "io"

// Backend creates one Session for each connection the server accepts. It is
// called from the connection's own goroutine, before the greeting, so a
// Backend that wants to refuse a connection (a blocklisted address, for
// instance) returns an *Error and the server sends it and hangs up.
type Backend interface {
	NewSession(c *Conn) (Session, error)
}

// BackendFunc adapts a function to the Backend interface.
type BackendFunc func(c *Conn) (Session, error)

// NewSession calls f.
func (f BackendFunc) NewSession(c *Conn) (Session, error) { return f(c) }

// Session is the Backend's view of one connection. The server calls its
// methods one at a time, in the order the client's commands arrive, so a
// Session needs no locking of its own, with one exception: while a message
// sent with BDAT is being read, Data runs while the next chunk is read from the
// client, and no other method is called until Data has returned.
//
// Every method answers with an error. nil accepts. An *Error chooses the reply
// exactly; any other error becomes a generic temporary failure (or, for Auth, a
// credential failure) and is logged, never sent. A Session decides every
// authorization: the server never relays or accepts a recipient on its own, and
// a Session embedded from RefuseSession refuses all of them until it overrides
// the method.
type Session interface {
	// Auth checks the credentials a client presented with AUTH PLAIN or AUTH
	// LOGIN. mechanism is "PLAIN" or "LOGIN". It is called only on a connection
	// that is allowed to authenticate (see Server.AllowInsecureAuth). The
	// server rate-limits failures per address before this is called, so it does
	// not have to.
	Auth(mechanism, username, password string) error

	// Mail starts a transaction for the reverse-path from, which is empty for a
	// null sender. opts is valid only until Mail returns.
	Mail(from string, opts *MailOptions) error

	// Rcpt adds one recipient. The reply is per recipient: returning an error
	// refuses this recipient and keeps the others. opts is valid only until
	// Rcpt returns.
	Rcpt(to string, opts *RcptOptions) error

	// Data reads the message, dot-unstuffed and with its CRLF line endings, up
	// to its end. r is valid only until Data returns. Reading past the
	// configured size makes r return ErrDataTooLarge. Returning nil accepts the
	// message for every recipient accepted by Rcpt.
	Data(r io.Reader) error

	// Reset is called when a transaction that Mail started ends, whether the
	// message was accepted or not, and on RSET, a second EHLO and STARTTLS. The
	// Session drops whatever it kept for the transaction.
	Reset()

	// Logout is called once, when the connection ends. After it returns the
	// Conn and the Session are not used again.
	Logout() error
}

// BodyType is the value of the BODY parameter of MAIL FROM.
type BodyType uint8

// The body types the server accepts. BINARYMIME is not offered.
const (
	// Body7Bit is the default, and what BODY=7BIT asks for.
	Body7Bit BodyType = iota
	// Body8BitMIME is what BODY=8BITMIME asks for.
	Body8BitMIME
)

// DSNReturn is the value of the RET parameter of MAIL FROM (RFC 3461): how much
// of the original message a delivery status notification carries back.
type DSNReturn uint8

// The RET values.
const (
	// ReturnDefault means the client did not say.
	ReturnDefault DSNReturn = iota
	// ReturnFull asks for the whole message.
	ReturnFull
	// ReturnHeaders asks for the headers only.
	ReturnHeaders
)

// DSNNotify is one value of the NOTIFY parameter of RCPT TO (RFC 3461).
type DSNNotify string

// The NOTIFY values. NotifyNever is never combined with another.
const (
	NotifyNever   DSNNotify = "NEVER"
	NotifySuccess DSNNotify = "SUCCESS"
	NotifyFailure DSNNotify = "FAILURE"
	NotifyDelay   DSNNotify = "DELAY"
)

// MailOptions is what the client sent with MAIL FROM besides the address. The
// server reuses one value for every transaction of a connection, so a Session
// that keeps it past the call to Mail copies it.
type MailOptions struct {
	// Size is the SIZE parameter: the size the client says the message has. It
	// is 0 when the client did not say.
	Size int64
	// Body is the BODY parameter.
	Body BodyType
	// UTF8 is true when the client sent SMTPUTF8, which allows non-ASCII
	// addresses and headers.
	UTF8 bool
	// Return is the DSN RET parameter.
	Return DSNReturn
	// EnvelopeID is the DSN ENVID parameter, decoded from xtext. A bounce built
	// for this message carries it back.
	EnvelopeID string
	// Auth is the AUTH parameter, decoded from xtext: the identity the sender
	// authenticated as. It is empty when absent or when the client sent <>.
	Auth string
}

// RcptOptions is what the client sent with RCPT TO besides the address. The
// server reuses one value for every recipient of a connection, so a Session
// that keeps it, or its Notify slice, past the call to Rcpt copies it.
type RcptOptions struct {
	// Notify is the DSN NOTIFY parameter, empty when the client did not say.
	Notify []DSNNotify
	// OriginalRecipientType is the address type of the DSN ORCPT parameter,
	// normally "rfc822" or "utf-8". It is empty when ORCPT is absent.
	OriginalRecipientType string
	// OriginalRecipient is the ORCPT address, decoded from xtext (or uxtext for
	// "utf-8"): the recipient the sender first named, before any forwarding.
	OriginalRecipient string
}

// RefuseSession is a Session that refuses everything, so the zero value of a
// custom Session is never an open relay. Embed it and override what the
// application allows.
//
// Auth answers ErrAuthFailed, Mail and Rcpt answer ErrRelayDenied, and Data
// answers ErrTempFailure (it is reached only if a Rcpt was accepted, which this
// type never does).
type RefuseSession struct{}

// Auth refuses every credential.
func (RefuseSession) Auth(string, string, string) error { return ErrAuthFailed }

// Mail refuses every sender.
func (RefuseSession) Mail(string, *MailOptions) error { return ErrRelayDenied }

// Rcpt refuses every recipient.
func (RefuseSession) Rcpt(string, *RcptOptions) error { return ErrRelayDenied }

// Data refuses every message.
func (RefuseSession) Data(io.Reader) error { return ErrTempFailure }

// Reset does nothing.
func (RefuseSession) Reset() {}

// Logout does nothing.
func (RefuseSession) Logout() error { return nil }

// RefuseBackend is the Backend that gives every connection a RefuseSession. A
// Server refuses to start without a Backend, and this is the explicit way to say
// "refuse everything": the greeting and the extensions are served, and nothing
// is accepted.
type RefuseBackend struct{}

// NewSession returns a RefuseSession.
func (RefuseBackend) NewSession(*Conn) (Session, error) { return RefuseSession{}, nil }
