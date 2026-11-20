# Working on Arandu SMTPD

This is an Arandu library module: an SMTP and ESMTP server (`Server`), the
interface an application implements to decide what it accepts (`Backend` and
`Session`), the limits and abuse protections around the protocol, a hot-reloading
TLS certificate (`CertReloader`), PROXY protocol, counters and `log/slog`
records. It is a Go module somebody `go get`s and imports, built on the Go
standard library alone.

It began as the package skeleton, configured as `hyz-is/smtpd`, and the HTTP
module the template ships was removed on purpose: there is no entity, no table,
no migration, no policy, no route and no `Module` to register. Nothing here
should grow back into one.

It serves two roles in the meeng.dev mail cluster, and any other application
that needs an SMTP server: the submission relay (ports 465, 587, 2465 and 2587,
`AUTH` with an API key as the password) and the inbound server (the MX of a
return-path domain, which receives delivery status notifications and feedback
reports).

Read `.agents/skills/` before writing code. Each skill is a procedure, and the
one you need is named by the situation you are in.

## The gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a preference. This checkout may sit beside a Go workspace
that does not list it; when it does, every command above fails before it
compiles anything. With the workspace off, the module resolves what `go.mod`
says, which is what CI compiles against.

A change to a parser also gets a run of its fuzzer (`go test -run '^$' -fuzz
FuzzDotReader -fuzztime 30s .`), and a change to the hot path gets the
benchmarks before and after. The numbers in `README.md` are measured, never
estimated: update them from a run, or leave them.

`aru doctor` is not one of the gates. It reads applications, and exits 1 here.

## What this repository holds

| | measured with |
| --- | --- |
| the root package `smtpd`, one directory, no subpackage | `ls *.go` |
| 0 imports outside the standard library, 0 `require` lines in `go.mod` | `TestThePackageUsesOnlyTheStandardLibrary` |
| 0 routes, 0 tables, 2 capabilities (`network`, `filesystem`) | `arandu.mod.toml`, `TestTheDeclaredCapabilitiesAreWhatTheCodeDoes` |
| 7 fuzz targets | `grep -c '^func Fuzz' *_test.go` |

## What does not exist here, on purpose

| A model reaches for | What is here instead |
| --- | --- |
| a list of domains the server accepts mail for, or a default that accepts | nothing. Every decision is the `Session`'s, and `RefuseSession` refuses all |
| a dependency for SASL, for PROXY protocol, for rate limiting, for a metrics registry | the standard library: the code is small and the surface is ours |
| `Stats` registered in a global Prometheus registry | `Server.Stats()`, a plain struct of numbers the application exports as it likes |
| a global logger or a package-level variable to configure | `Server.Logger`, a field; the package has no mutable package-level state |
| `bufio.Reader.ReadString`, `fmt.Fprintf` or `strings.Split` on the command path | `ReadSlice`, hand-written replies and byte slices: the hot path allocates nothing |
| treating a bare LF as a line end, or reading the message with `net/textproto.DotReader` | `dotReader`, which ends a message at `<CRLF>.<CRLF>` only |
| the Session buffering a `BDAT` message in memory | `Session.Data` runs in a goroutine over a pipe, so a chunked message streams like a `DATA` one |
| `time.Sleep` in a handler for the tarpit | a timer that also watches `Server.done`, so shutdown is not held up |
| closing a listener and walking the connections to close them | `Shutdown`, which wakes the idle ones with a read deadline and lets a message in progress finish |

## The properties

A change that breaks one of them is not merged, whatever else it improves.

1. **It never relays.** There is no path on which a recipient is accepted
   without the Session saying yes.
2. **The end of a message is `<CRLF>.<CRLF>`.** A bare line feed neither ends a
   message nor starts a line.
3. **A refusal keeps the connection in step.** The data of a refused `DATA` or
   `BDAT` is read and discarded, up to a bound, before the connection goes on.
4. **No internal detail reaches the client.** Only an `*Error` is sent as it is.
5. **A limit is a limit.** Connections, recipients, size, line length, errors and
   time are checked before the work they bound, and every one has a test.
6. **Nothing allocates on the hot path.** `TestParsingDoesNotAllocate` and the
   benchmarks hold it.
7. **`arandu.mod.toml` matches the code.**

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests.

Every exported symbol carries a doc comment, and the comment documents the
symbol and nothing else. A date, an issue number, a version in progress or the
name of another repository does not belong in it.

Tests that use the package as a caller does live in `tests/Unit` and declare
`package unit_test`. Tests of the unexported parsers, the fuzz tests and the
benchmarks of the hot path live beside the code in `*_internal_test.go` files.
No test leaves the machine.

Commit messages are in English, say what changed and why, and carry no
attribution to any AI tool: no `Co-Authored-By`, no "Generated with", no vendor
name. The identity is `HYZIS <admin@hyz.is>`, set in the repository's own
`git config`, never with `--author`.
