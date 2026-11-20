package smtpd

import (
	"errors"
	"strconv"
)

// Error is an SMTP reply a Backend or Session asks the server to send. Any
// other error returned from a Session method is answered with a generic reply
// that carries no detail of the error, so an internal failure never reaches the
// client: only an *Error is written to the wire as it is.
type Error struct {
	// Code is the three-digit SMTP reply code: 2xx accepts, 4xx asks the client
	// to try again later, 5xx refuses for good.
	Code int
	// Enhanced is the RFC 3463 status code, such as "5.7.1". It may be empty,
	// and then the reply carries none.
	Enhanced string
	// Message is the human-readable text. A newline starts a continuation line
	// of a multi-line reply; carriage returns are dropped.
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	b := make([]byte, 0, 16+len(e.Message))
	b = append(b, "smtp: "...)
	b = strconv.AppendInt(b, int64(e.Code), 10)
	if e.Enhanced != "" {
		b = append(b, ' ')
		b = append(b, e.Enhanced...)
	}
	b = append(b, ' ')
	b = append(b, e.Message...)
	return string(b)
}

// Temporary reports whether the reply asks the client to try again later.
func (e *Error) Temporary() bool { return e.Code >= 400 && e.Code < 500 }

// The replies a Backend most often needs. They are values, so a Backend returns
// them as they are and a caller compares them with errors.Is.
var (
	// ErrAuthFailed answers a credential the Backend does not accept.
	ErrAuthFailed = &Error{535, "5.7.8", "Authentication credentials invalid"}
	// ErrAuthRequired answers a command that needs a prior AUTH.
	ErrAuthRequired = &Error{530, "5.7.0", "Authentication required"}
	// ErrRelayDenied answers a recipient the server will not relay for. It is
	// the reply the RefuseSession gives, so an unconfigured server is never an
	// open relay.
	ErrRelayDenied = &Error{554, "5.7.1", "Relay access denied"}
	// ErrMailboxUnavailable answers a recipient that does not exist here.
	ErrMailboxUnavailable = &Error{550, "5.1.1", "Mailbox unavailable"}
	// ErrTempFailure answers anything that may work if the client tries again.
	ErrTempFailure = &Error{451, "4.3.0", "Temporary failure, try again later"}
	// ErrDataTooLarge answers a message above the configured size. It is also
	// what the reader given to Session.Data returns once the limit is passed,
	// so a Backend that returns the read error unchanged gets the right reply.
	ErrDataTooLarge = &Error{552, "5.3.4", "Message size exceeds fixed limit"}
)

// Replies the server itself sends. Package-level values, so choosing one costs
// nothing at run time.
var (
	errSyntax         = &Error{500, "5.5.1", "Command not recognized"}
	errSyntaxArgs     = &Error{501, "5.5.4", "Syntax error in parameters or arguments"}
	errLineTooLong    = &Error{500, "5.5.2", "Line too long"}
	errNotImplemented = &Error{502, "5.5.1", "Command not implemented"}
	errBadSequence    = &Error{503, "5.5.1", "Bad sequence of commands"}
	errParamNotSupp   = &Error{555, "5.5.4", "Parameter not recognized or not implemented"}
	errNeedHello      = &Error{503, "5.5.1", "Send HELO/EHLO first"}
	errNestedMail     = &Error{503, "5.5.1", "Nested MAIL command"}
	errNeedMail       = &Error{503, "5.5.1", "Need MAIL before RCPT"}
	errNeedRcpt       = &Error{554, "5.5.1", "No valid recipients"}
	errTooManyRcpt    = &Error{452, "4.5.3", "Too many recipients"}
	errTLSRequired    = &Error{530, "5.7.0", "Must issue a STARTTLS command first"}
	errAlreadyTLS     = &Error{503, "5.5.1", "TLS already active"}
	errNoTLS          = &Error{502, "5.5.1", "STARTTLS not available"}
	errAuthNeedsTLS   = &Error{538, "5.7.11", "Encryption required for requested authentication mechanism"}
	errAlreadyAuthed  = &Error{503, "5.5.1", "Already authenticated"}
	errAuthInProgress = &Error{503, "5.5.1", "AUTH not allowed during a mail transaction"}
	errAuthSyntax     = &Error{501, "5.5.2", "Cannot decode the authentication response"}
	errAuthCancelled  = &Error{501, "5.0.0", "Authentication cancelled"}
	errAuthMechanism  = &Error{504, "5.5.4", "Unrecognized authentication type"}
	errAuthBlocked    = &Error{454, "4.7.0", "Too many failed authentication attempts, try again later"}
	errTooManyErrors  = &Error{421, "4.7.0", "Too many errors, closing connection"}
	errShutdown       = &Error{421, "4.3.2", "Service shutting down, closing connection"}
	errIdleTimeout    = &Error{421, "4.4.2", "Idle timeout, closing connection"}
	errTooManyConns   = &Error{421, "4.3.2", "Too many connections, try again later"}
	errTooManyConnsIP = &Error{421, "4.7.0", "Too many connections from your address, try again later"}
	errEarlyTalker    = &Error{554, "5.5.0", "Protocol error: the client spoke before the greeting"}
	errPipelinedTLS   = &Error{554, "5.5.1", "Commands were pipelined after STARTTLS"}
	errBareLF         = &Error{550, "5.6.0", "Message contains a bare line feed"}
	errBadChunk       = &Error{501, "5.5.4", "BDAT needs a chunk size and optionally LAST"}
	errDataAfterBDAT  = &Error{503, "5.5.1", "DATA is not allowed after BDAT"}
	errChunkingOff    = &Error{502, "5.5.1", "CHUNKING not available"}
	errNeedUTF8       = &Error{553, "5.6.7", "Non-ASCII address requires SMTPUTF8"}
	errBadAddress     = &Error{501, "5.1.7", "Bad address syntax"}
	errSizeExceeded   = &Error{552, "5.3.4", "Message size exceeds fixed limit"}
	errBackendFailed  = &Error{451, "4.3.0", "Temporary failure, try again later"}
	errVRFY           = &Error{252, "2.5.2", "Cannot VRFY user, but will accept message and attempt delivery"}
	errRSETOK         = &Error{250, "2.0.0", "Ok"}
	errNoopOK         = &Error{250, "2.0.0", "Ok"}
	errHelpOK         = &Error{214, "2.0.0", "See RFC 5321"}
	errDataGo         = &Error{354, "", "End data with <CR><LF>.<CR><LF>"}
	errQuitOK         = &Error{221, "2.0.0", "Bye"}
	errStartTLSGo     = &Error{220, "2.0.0", "Ready to start TLS"}
	errMailOK         = &Error{250, "2.1.0", "Ok"}
	errRcptOK         = &Error{250, "2.1.5", "Ok"}
	errDataOK         = &Error{250, "2.0.0", "Ok: queued"}
	errAuthOK         = &Error{235, "2.7.0", "Authentication successful"}
)

// asError turns whatever a Session returned into the reply to send. An *Error
// is used as it is; anything else becomes fallback, and the detail of the
// original error stays in the log.
func asError(err error, fallback *Error) *Error {
	if se, ok := err.(*Error); ok {
		return se
	}
	var se *Error
	if errors.As(err, &se) {
		return se
	}
	return fallback
}

var errNoSession = &Error{421, "4.3.0", "Service not available"}
