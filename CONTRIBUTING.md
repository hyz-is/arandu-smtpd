# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the four gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a habit: this checkout may sit beside a Go workspace that
does not list it, and then every command fails before it compiles anything.

A change to a parser comes with a fuzz seed or a test that reproduces what it
fixes. Run the fuzzer on what you touched:

```bash
go test -run '^$' -fuzz FuzzDotReader -fuzztime 30s .
```

A change to the hot path (the command parser, the replies, the `DATA` reader)
comes with the benchmark before and after:

```bash
go test -run '^$' -bench . -benchtime 3s ./tests/Unit
go test -run '^$' -bench 'DotReader|SplitCommand' .
```

## What a change has to keep true

1. **It never relays.** The server has no default that accepts: every sender,
   recipient and message is the Session's decision, and `RefuseSession` refuses
   them all.
2. **The end of data is `<CRLF>.<CRLF>`.** Nothing else ends a message, and a
   bare line feed is not a line end.
3. **A refusal keeps the connection in step.** When a command carries data (a
   message, a `BDAT` chunk), the data is read and thrown away before the
   refusal is the last word.
4. **The hot path does not allocate.** Command parsing, replies, the `DATA`
   reader and the `EHLO` reply stay at zero allocations, and
   `TestParsingDoesNotAllocate` holds it.
5. **No detail of an internal error reaches a client.** Only an `*Error` is
   written to the wire as it is.
6. **This stays a library of the standard library.** No dependency, no route,
   no table, no `init`. `TestThePackageUsesOnlyTheStandardLibrary` and
   `TestThePackageIsALibrary` hold it.
7. **`arandu.mod.toml` matches the code.** A new capability is declared there in
   the same commit.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests. `pkg.go.dev`
publishes the doc comments, and its readers are users of this package.

Every exported symbol carries a doc comment saying what it does. The comment
documents the symbol and nothing else: no dates, no issue numbers, no references
to other repositories.

Tests that use the package as a caller does live in `tests/Unit`, declaring
`package unit_test`. Tests of unexported parsers and the fuzz tests live beside
the code, in `*_internal_test.go` files. No test calls anything outside the
machine: clients and servers talk over loopback or `net.Pipe`.

## Commits

One commit per logical change. Formatting is not mixed with behaviour, because a
diff that does both is a diff nobody reviews.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-smtpd.
