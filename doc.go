// Package smtpd is an SMTP and ESMTP server for Go applications: the protocol,
// the limits that keep it from being abused, and a Backend interface where the
// application decides what to accept. It uses the standard library only.
//
// An application implements Backend, which gives one Session to each
// connection. The Session answers AUTH, MAIL, RCPT and DATA, one recipient at
// a time, and the server does the rest:
//
//	type session struct{ smtpd.RefuseSession; from string }
//
//	func (s *session) Mail(from string, _ *smtpd.MailOptions) error { s.from = from; return nil }
//	func (s *session) Rcpt(to string, _ *smtpd.RcptOptions) error {
//		if !ourDomain(to) {
//			return smtpd.ErrRelayDenied
//		}
//		return nil
//	}
//	func (s *session) Data(r io.Reader) error { return enqueue(s.from, r) }
//
//	srv := &smtpd.Server{
//		Backend:   smtpd.BackendFunc(func(*smtpd.Conn) (smtpd.Session, error) { return &session{}, nil }),
//		Hostname:  "mx.example.com",
//		TLSConfig: reloader.TLSConfig(), // from smtpd.NewCertReloader
//	}
//	go srv.ListenAndServe(":25")     // STARTTLS
//	go srv.ListenAndServeTLS(":465") // TLS from the first byte
//
// # What the server speaks
//
// HELO and EHLO; STARTTLS; AUTH PLAIN and AUTH LOGIN, offered only inside TLS
// unless Server.AllowInsecureAuth says otherwise; MAIL, RCPT, DATA, RSET, NOOP,
// QUIT, VRFY, HELP; and the extensions PIPELINING, SIZE, 8BITMIME, SMTPUTF8,
// ENHANCEDSTATUSCODES, CHUNKING (BDAT) and DSN. The DSN parameters (RET, ENVID,
// NOTIFY, ORCPT) arrive decoded in MailOptions and RcptOptions.
//
// # What it protects against
//
// The server never relays: a Session that does not say yes to a recipient
// leaves it refused, and RefuseSession, which refuses everything, is the base to
// embed. Beyond that it enforces, with defaults that are safe for the open
// internet:
//
//   - a limit on connections, in all and per client (an IPv6 /64 counts as one
//     client), and on recipients, message size, command line length and errors
//     per connection;
//   - a timeout on every command, on a whole message and on every write;
//   - a limit on failed AUTH attempts per client, with a pause that doubles on
//     each failure and a block for a while once the limit is reached;
//   - early-talker detection, optional, which hangs up on a client that
//     sends before the greeting;
//   - a strict end of data (only CRLF.CRLF), with optional refusal of bare line
//     feeds, so SMTP smuggling does not work, and a refusal of commands that
//     arrive pipelined behind STARTTLS;
//   - optional PROXY protocol, versions 1 and 2, from trusted proxies only.
//
// # Operation
//
// CertReloader serves a certificate from files and replaces it when they
// change. Server.Shutdown stops accepting, hangs up on idle connections and
// lets a message in progress finish. Server.Stats gives atomic counters for a
// metrics exporter, and Server.Logger receives log/slog records that carry the
// connection and session ids.
//
// 0 in a numeric field of Server means the default, and a negative number means
// no limit, so the zero Server is a safe one.
package smtpd
