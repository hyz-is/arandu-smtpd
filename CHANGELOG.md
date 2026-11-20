# Changelog

Everything worth knowing about a release of Arandu SMTPD is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- `Server`, an SMTP and ESMTP server with plain listeners (`Serve`,
  `ListenAndServe`, `STARTTLS`) and implicit-TLS listeners (`ServeTLS`,
  `ListenAndServeTLS`), `Shutdown` and `Close`.
- `Backend`, `Session`, `Conn`, `MailOptions`, `RcptOptions` and `Error`: the
  interface the application implements, with one answer per recipient, the DSN
  parameters (`RET`, `ENVID`, `NOTIFY`, `ORCPT`) handed over decoded, and
  `RefuseSession` and `RefuseBackend` so that nothing is relayed unless the
  application says so.
- `HELO`, `EHLO`, `STARTTLS`, `AUTH PLAIN` and `AUTH LOGIN`, `MAIL`, `RCPT`,
  `DATA`, `BDAT`, `RSET`, `NOOP`, `QUIT`, `VRFY`, `HELP`, and the extensions
  `PIPELINING`, `SIZE`, `8BITMIME`, `SMTPUTF8`, `ENHANCEDSTATUSCODES`,
  `CHUNKING` and `DSN`.
- Limits: connections in all and per client, recipients, message size, command
  line length, errors per connection, a timeout for each command, for a whole
  message and for each write.
- Abuse protection: failed-`AUTH` limit per client with a block, a pause that
  doubles on each failure, early-talker detection, strict end of data (SMTP
  smuggling), refusal of commands pipelined behind `STARTTLS`, optional
  `RejectBareLF`.
- PROXY protocol versions 1 and 2, from trusted proxies only.
- `CertReloader`: a certificate served from files and replaced when they change.
- `Stats`, atomic counters for a metrics exporter, and `log/slog` records with
  the connection and session ids.
- Fuzz tests for every parser and for the whole conversation, and benchmarks of
  sessions per second and messages per second.
