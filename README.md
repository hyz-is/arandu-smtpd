<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu SMTPD

An SMTP and ESMTP server for Go: the protocol, the limits that keep it from
being abused, and a `Backend` interface where the application decides what it
accepts. It uses the Go standard library and nothing else.

It is a library. It registers no route, owns no table and decides no
authorization. An application writes a `Session`, builds one `Server`, and
gives it listeners. It serves two roles with the same code: a submission relay
(ports 465, 587 and their alternatives, `AUTH` with a secret as the password)
and an inbound server (the MX of a return-path domain, which receives bounces
and feedback reports).

## Install

```bash
go get github.com/hyz-is/arandu-smtpd
```

## A server in one screen

```go
type session struct {
	smtpd.RefuseSession // anything not overridden below is refused
	from  string
	rcpts []string
}

func (s *session) Mail(from string, _ *smtpd.MailOptions) error { s.from = from; return nil }

func (s *session) Rcpt(to string, _ *smtpd.RcptOptions) error {
	if !ours(to) {
		return smtpd.ErrRelayDenied // one answer per recipient
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error { return enqueue(s.from, s.rcpts, r) }
func (s *session) Reset()                 { s.from, s.rcpts = "", s.rcpts[:0] }

srv := &smtpd.Server{
	Backend:   smtpd.BackendFunc(func(*smtpd.Conn) (smtpd.Session, error) { return &session{}, nil }),
	Hostname:  "mx.example.com",
	TLSConfig: reloader.TLSConfig(),
}
go srv.ListenAndServe(":25")     // STARTTLS
go srv.ListenAndServeTLS(":465") // TLS from the first byte
```

`example_test.go` has the two complete shapes: a submission relay and an inbound
server behind a load balancer.

## The Backend and the Session

`Backend.NewSession(*Conn)` is called once for each connection, before the
greeting. Returning an `*Error` refuses the connection with that reply.

| `Session` method | called when | what the return value does |
| --- | --- | --- |
| `Auth(mechanism, username, password)` | `AUTH PLAIN` or `AUTH LOGIN`, on a connection allowed to authenticate | `nil` is `235`; any other error is `535` |
| `Mail(from, *MailOptions)` | `MAIL FROM` | `nil` starts the transaction; an error refuses the sender |
| `Rcpt(to, *RcptOptions)` | each `RCPT TO` | an error refuses **that recipient** and keeps the others |
| `Data(io.Reader)` | `DATA`, or the chunks of `BDAT` | `nil` accepts the message for every accepted recipient |
| `Reset()` | a transaction ends (accepted or not), `RSET`, a second `EHLO`, `STARTTLS` | forget the transaction |
| `Logout()` | the connection ends | |

An `*Error` (`Code`, `Enhanced`, `Message`) is written to the client as it is.
Any other error is logged and answered with a generic `451 4.3.0`, so what the
application failed on never reaches the client. `ErrAuthFailed`,
`ErrAuthRequired`, `ErrRelayDenied`, `ErrMailboxUnavailable`, `ErrTempFailure`
and `ErrDataTooLarge` are ready to return.

**The server never relays.** It has no list of domains and no default policy of
"accept": every sender, recipient and message is the Session's decision.
`RefuseSession` refuses everything; embed it, and the methods you do not
override stay refused. A Session whose `Rcpt` says `nil` for a recipient it does
not own is an open relay, and the server cannot tell.

`MailOptions` and `RcptOptions` carry what the client sent with the addresses:
`SIZE`, `BODY`, `SMTPUTF8`, and the DSN parameters `RET`, `ENVID` (decoded from
xtext), `NOTIFY`, and `ORCPT` (xtext or uxtext decoded), so a bounce built later
can honour them. The server reuses one value of each for a connection: copy what
you keep.

`*Conn` tells the Session who is calling: `ID`, `SessionID`, `RemoteAddr` (the
address from the PROXY header when there is one), `LocalAddr`, `Hostname` (the
EHLO name), `TLS`, `Username`.

## What it speaks

`HELO`, `EHLO`, `STARTTLS`, `AUTH PLAIN` and `AUTH LOGIN`, `MAIL`, `RCPT`,
`DATA`, `BDAT`, `RSET`, `NOOP`, `QUIT`, `VRFY` (answers `252`, confirms
nothing), `HELP`; and the extensions `PIPELINING`, `SIZE`, `8BITMIME`,
`SMTPUTF8`, `ENHANCEDSTATUSCODES`, `CHUNKING` and `DSN`. `AUTH` is offered only
inside TLS, unless `AllowInsecureAuth` is set, and not after the client has
authenticated. `Disable*` fields remove an extension from the `EHLO` reply.

A message sent with `BDAT` is streamed: `Session.Data` runs while the chunks
arrive, reading from a pipe, so a large message is never held in memory whole.

## Protections

Every number below is a field of `Server`. `0` means the default shown and a
negative number means no limit, so the zero `Server` is a safe one.

| Protection | Field | Default |
| --- | --- | --- |
| connections open, in all | `MaxConnections` | 10000 |
| connections per client (an IPv6 /64 is one client) | `MaxConnectionsPerIP` | 100 |
| recipients in a transaction | `MaxRecipients` | 100 (`452 4.5.3` past it) |
| message size | `MaxMessageBytes` | 10 MiB (`552 5.3.4`; the rest of the message is read and thrown away, so the connection stays in step) |
| refused commands before `421` and hang-up | `MaxErrors` | 10 |
| command line length | `MaxLineLength` | 4096 |
| time for the next command | `CommandTimeout` | 5 minutes |
| time for a whole message | `DataTimeout` | 10 minutes |
| time for the client to take a reply | `WriteTimeout` | 1 minute |
| TLS handshake and PROXY header | `HandshakeTimeout` | 30 seconds |
| failed `AUTH` per client | `MaxAuthFailures` in `AuthFailureWindow` | 10 in 10 minutes, then blocked for `AuthBlockDuration` (15 minutes): `454`, and the Session is not asked |
| pause before the answer to a failed `AUTH` | `AuthFailureDelay` | 1 second, doubling per failure on the connection up to `AuthFailureDelayMax` (10 seconds) |
| client that speaks before the greeting | `EarlyTalkerDelay` | off; a positive value waits that long and answers `554 5.5.0` |
| bare line feeds in a message | `RejectBareLF` | off; the end of a message is `<CRLF>.<CRLF>` and nothing else either way |
| `AUTH` and `MAIL` without TLS or without `AUTH` | `AllowInsecureAuth`, `RequireTLS`, `RequireAuth` | AUTH only inside TLS; the other two off |

Three of them deserve a sentence each.

- **SMTP smuggling.** A bare line feed is not a line end: the dot after one is
  not stuffing and cannot end a message. A server and a proxy that disagree
  about that are how a second message is smuggled inside the first.
- **STARTTLS injection.** Commands that arrive in the same packet as `STARTTLS`
  would run after the handshake with the client's credentials. The server
  answers `554 5.5.1` and hangs up instead.
- **A guessing run spread over many connections.** The failure count is per
  client, not per connection, and a blocked client is refused before the
  Session is asked, so the right password does not work while it is blocked
  either.

### Behind a load balancer

`ProxyProtocol` makes every connection start with a PROXY protocol header,
version 1 or 2, and uses the address in it as the client's, for the limits, the
log and `Conn.RemoteAddr`. A connection that does not start with one is
dropped. `ProxyTrusted` limits whose header is believed: a connection from
anywhere else is dropped before the header is read.

## TLS and certificate renewal

`TLSConfig` turns on `STARTTLS` for `Serve`/`ListenAndServe` and is the
configuration of `ServeTLS`/`ListenAndServeTLS`. The server clones it and raises
`MinVersion` to TLS 1.2.

`CertReloader` serves a certificate from files and replaces it when they
change, so a renewal reaches new connections without a restart:

```go
reloader, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{
	CertFile: "/certs/server.crt",
	KeyFile:  "/certs/server.key",
	Interval: 5 * time.Minute,
})
reloader.Start(ctx)
srv.TLSConfig = reloader.TLSConfig() // or: &tls.Config{GetCertificate: reloader.GetCertificate}
```

It compares the content of the files and reads the paths again on every check,
so a renewal that swaps a symlink (certbot's `live/` directory does) is seen. A
renewal caught half-written, or a key that does not match the certificate, is
refused and the certificate in use stays. It logs a warning every check once
the certificate is within `ExpiryWarning` (14 days) of expiring. `Check()`
runs one poll by hand.

## Shutdown, logs and metrics

`Shutdown(ctx)` closes the listeners, answers `421 4.3.2` to connections that
are waiting for a command, lets a message in progress finish, and returns when
the last connection is gone or `ctx` ends (and then closes the rest). `Close()`
closes everything at once.

`Logger` is a `*slog.Logger`. Every record carries `conn` (the connection
number), `session` (a string for the logs and for the Backend to store) and
`remote`. The default discards them.

`Stats()` returns atomic counters ready for a metrics exporter:
`ConnsAccepted`, `ConnsRefused`, `ConnsActive` (a gauge), `Sessions`, `Commands`,
`ProtocolErrors`, `Messages`, `MessagesRefused`, `DataBytes`, `RcptAccepted`,
`RcptRefused`, `AuthSuccess`, `AuthFailure`, `AuthBlocked`, `TLSHandshakes`,
`TLSFailures`, `EarlyTalkers`, `Timeouts`, `ProxyHeaders`, `ProxyFailures` and
`Panics`. A panic in a Session closes that connection and is counted; it does
not stop the server.

## Performance

Measured on an Apple M4 Max (14 cores), Go 1.26.6, with the server and its
clients in one process over loopback, so the clients take CPU the server would
have. The Session discards the message.

```bash
go test -run '^$' -bench . -benchtime 3s ./tests/Unit
```

| Benchmark | Result |
| --- | --- |
| a whole session (connect, greeting, `EHLO`, `QUIT`, close) | 22,000 sessions/s |
| 1 KiB message, `MAIL`/`RCPT`/`DATA` pipelined in one write | 104,000 messages/s, 2 allocations per message |
| 1 KiB message, `BDAT` | 112,000 messages/s |
| 1 KiB message, one command at a time (4 round trips) | 28,000 messages/s |
| 100 KiB message, pipelined | 58,600 messages/s, 6.0 GB/s |
| 1 MiB message, pipelined | 9,800 messages/s, 10.3 GB/s |
| one connection, one 1 KiB message at a time | 13 µs per message |
| the `DATA` reader alone (`go test -bench DotReader .`) | 7.8 GB/s |
| parsing a `MAIL FROM` with its parameters | 66 ns, 0 allocations |

The two allocations of a message are the strings of the sender and the
recipient, which the `Session` interface hands over. Command parsing, replies,
the `DATA` reader and the `EHLO` reply allocate nothing: the buffers come from
pools, the `EHLO` reply is built once, and the reader copies a line at a time
with `bytes.IndexByte`.

## Tests

`go test -race ./...` runs the standard library's `net/smtp` as a client, raw
conversations (pipelining, `BDAT`, errors, limits, TLS, PROXY, shutdown), the
certificate reload against real files and symlinks, and a model of the `DATA`
reader that it is compared against on every input the fuzzer finds. Every parser
has a fuzz test (`go test -fuzz FuzzDotReader .`), and `FuzzConversation` feeds
random bytes through the whole server.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
