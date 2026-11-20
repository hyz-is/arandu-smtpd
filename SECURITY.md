# Security policy

## Supported versions

The latest minor release of Arandu SMTPD receives security fixes. Older minor
releases do not: a published Go module version is immutable, so a fix is a new
release rather than a moved tag.

## Reporting a vulnerability

Report it privately, through GitHub's advisory form:

<https://github.com/hyz-is/arandu-smtpd/security/advisories/new>

Do not open a public issue and do not describe the problem in a pull request. A
report that arrives in public is a report every reader of this repository can
act on before there is a release to upgrade to.

Include what you need to reproduce it: the version, the bytes the client sent
(a capture of the conversation is the best report), and what the server did.
Never a real credential.

Expect an acknowledgement within a few days. If the report is confirmed, the
fix, the release and the advisory are published together, and you are credited
unless you ask not to be.

## What is in scope

Anything that lets a client do what the server promises it cannot, or that
breaks an application that trusts the server's limits. In particular:

- a message that ends where the specification says it does not (SMTP
  smuggling), or a command that runs when it was sent inside the data of
  another;
- a command pipelined behind `STARTTLS` that runs after the handshake;
- `AUTH` accepted before TLS when `AllowInsecureAuth` is off, or a credential
  checked while the client is blocked for failing too often;
- a Session method called when the server's own rules say it must not be (a
  `Rcpt` before `Mail`, a `Data` with no accepted recipient);
- a message larger than `MaxMessageBytes` delivered to a Session, or a limit
  (connections, recipients, errors, line length, time) that a client can
  exceed;
- the text of an internal error, or a credential, reaching a client or a log
  line;
- a PROXY protocol header believed from a peer that is not in `ProxyTrusted`;
- a panic, a deadlock or unbounded memory use on any input.

## What is not

- A Session that accepts a recipient it should not. The server never decides
  who it relays for; the application's Session does.
- A vulnerability in the Go standard library or in `crypto/tls`. Report that to
  the Go project.
- Denial of service by a client that holds the maximum number of connections
  the limits allow. The limits are the answer, and they are configurable.
