---
name: smtpd-package
description: Install, wire and use Arandu SMTPD (github.com/hyz-is/arandu-smtpd, an SMTP and ESMTP server) in an Arandu application. Use when the request is to "receive mail", "accept SMTP", "write an SMTP server", "a submission relay", "SMTP AUTH with an API key", "an MX that receives bounces", "receive DSN and ARF reports", "listen on port 25, 465 or 587", "go get github.com/hyz-is/arandu-smtpd", "the client cannot AUTH", "Relay access denied", "STARTTLS does not work", "the certificate was renewed and the server still serves the old one", "too many connections", "behind a load balancer the address is always the balancer's", or when a project's go.mod already requires github.com/hyz-is/arandu-smtpd. Covers the Session to write, what the server decides and what it leaves to the Session, the listeners, TLS and its renewal, the PROXY protocol, the limits, shutdown, and the symptoms of each missing piece.
license: MIT
metadata:
  audience: app
---

# Using Arandu SMTPD

The server speaks SMTP and enforces limits. **The application decides what it
accepts**, in a `Session`. The server never relays on its own.

## 1. The Session

Embed `smtpd.RefuseSession`, so what is not overridden is refused, and override
what the application allows:

```go
type session struct {
	smtpd.RefuseSession
	app   *App
	key   string   // set by Auth
	from  string
	rcpts []string
}

func (s *session) Auth(mechanism, user, pass string) error {
	k, err := s.app.CheckAPIKey(pass) // constant-time, looked up by hash
	if err != nil {
		return smtpd.ErrAuthFailed
	}
	s.key = k.ID
	return nil
}
func (s *session) Mail(from string, o *smtpd.MailOptions) error { s.from = from; return nil }
func (s *session) Rcpt(to string, o *smtpd.RcptOptions) error {
	// one answer per recipient: refuse this one, keep the others
	s.rcpts = append(s.rcpts, to)
	return nil
}
func (s *session) Data(r io.Reader) error { return s.app.Accept(s.key, s.from, s.rcpts, r) }
func (s *session) Reset()                 { s.from, s.rcpts = "", s.rcpts[:0] }
```

- `Data` gets a reader that ends at the end of the message and returns
  `smtpd.ErrDataTooLarge` past `MaxMessageBytes`. Return the read error as it
  is and the client gets the right `552`.
- `MailOptions` and `RcptOptions` are reused by the server for the next command:
  copy what you keep (`Notify` is a slice).
- An error that is not an `*smtpd.Error` is logged and answered with a generic
  `451`. Return an `*smtpd.Error` to choose the reply (`Code`, `Enhanced`,
  `Message`).
- The tenant of what is accepted comes from what `Auth` verified, never from
  anything the client wrote in the envelope or the headers.

## 2. The Server and its listeners

```go
srv := &smtpd.Server{
	Backend:     smtpd.BackendFunc(func(c *smtpd.Conn) (smtpd.Session, error) { return &session{app: app}, nil }),
	Hostname:    "relay.example.com",
	TLSConfig:   reloader.TLSConfig(),
	RequireAuth: true,                       // a submission relay; leave off for an MX
	DisableAuth: false,                      // true for an MX: no AUTH at all
	Logger:      logger,
}
go srv.ListenAndServeTLS(":465")  // TLS from the first byte
go srv.ListenAndServe(":587")     // STARTTLS
```

The same `Server` serves any number of listeners; they share their limits and
counters. `Serve(l)` and `ServeTLS(l)` take a listener you built.

## 3. TLS and renewal

`AUTH` is offered only inside TLS. A `TLSConfig` with a certificate is
required for `ServeTLS`, and for `STARTTLS` to be offered. Build it from a
`CertReloader`, so a renewal reaches new connections without a restart:

```go
reloader, err := smtpd.NewCertReloader(smtpd.CertReloaderConfig{CertFile: cert, KeyFile: key, Logger: logger})
reloader.Start(ctx)
```

Certificate paths come from the environment, never from the repository.

## 4. Behind a load balancer

Set `ProxyProtocol: true` and `ProxyTrusted` to the balancer's networks.
Every connection then must begin with a PROXY header (v1 or v2), the limits and
the logs use the client's address, and `Conn.RemoteAddr()` is the client's.
Without it every client is the balancer, and `MaxConnectionsPerIP` refuses
everyone after the first hundred.

## 5. Shutdown and metrics

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
srv.Shutdown(ctx)
```

`srv.Stats()` is a struct of numbers: export it with the application's own
metrics. A panic in a Session closes its connection and counts in
`Stats().Panics`.

## Symptoms

| Symptom | Piece |
| --- | --- |
| `554 5.7.1 Relay access denied` | `Rcpt` is not overridden, or refuses; embed `RefuseSession` and override it |
| `538 5.7.11 Encryption required` on `AUTH` | the client authenticates before `STARTTLS`; use TLS, or `AllowInsecureAuth` on a trusted network only |
| `STARTTLS` is not in the `EHLO` reply | `TLSConfig` is nil, or the listener was started with `ServeTLS` (already encrypted) |
| `454 4.7.0 Too many failed authentication attempts` | the client failed `MaxAuthFailures` times; `AuthBlockDuration` passes, or fix its key |
| `421 4.7.0 Too many connections from your address` | `MaxConnectionsPerIP`; behind a balancer, set `ProxyProtocol` |
| `552 5.3.4` | the message is larger than `MaxMessageBytes` |
| `554 5.5.1 Commands were pipelined after STARTTLS` | the client sent commands before the handshake finished; this is refused on purpose |
| the old certificate is still served | `CertReloader.Start` was not called, or the files do not form a pair: see its log |
| every client has the balancer's address | `ProxyProtocol` is off |
