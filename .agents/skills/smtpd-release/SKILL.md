---
name: smtpd-release
description: Get this Arandu package green, measured and published. Use when the request is to "run the gates", "the tests fail", "go build says the directory prefix does not contain modules listed in go.work", "run the fuzzers", "run the benchmarks", "update the numbers in the README", "update arandu.mod.toml", "add a dependency", "tag a release", "publish it", "write the changelog", or before opening a pull request. Covers the four gates, the fuzz targets, the benchmarks and where their numbers live, what the manifest declares and who checks it, why the module has no dependency, and the immutability of a published module version.
license: MIT
---

# Getting it green, measured and out

## The four gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a habit. This checkout may sit beside a Go workspace that
does not list it. When it does, `go build ./...` exits 1 before compiling
anything: `directory prefix . does not contain modules listed in go.work`. With
the workspace off, the module resolves what `go.mod` says.

`aru doctor` is not a gate. It reads applications, and this is a library.

## The fuzzers

Every parser has a fuzz target, and `go test` runs their seeds. After changing
one, run it for real:

```sh
for f in FuzzDotReader FuzzSplitCommand FuzzMailAndRcptArguments FuzzXText \
         FuzzCheckAddress FuzzProxyHeader FuzzConversation; do
  go test -run '^$' -fuzz "^$f\$" -fuzztime 30s .
done
```

A failure writes its input to `testdata/fuzz/<Target>/`. Read it before deciding
what is wrong: it is either a bug in the code (fix the code and add the case to
the table test of that parser, so the fix does not depend on a corpus file) or
an invariant of the fuzz target that was too strong (fix the target). Do not
delete the input and move on.

`FuzzDotReader` compares the reader with `model` in `data_internal_test.go`,
which is the plain reading of RFC 5321 section 4.5.2. A change to what ends a
message changes the model first, with the reason.

## The benchmarks

```sh
go test -run '^$' -bench . -benchtime 3s ./tests/Unit
go test -run '^$' -bench 'DotReader|SplitCommand|Pipe' .
```

The numbers in `README.md`, "Performance", come from these runs on the machine
named there. Update them from a run, and name the machine if it changed; never
write a number that was not measured. A change to the command path that raises
allocations, or lowers a result by more than the noise, is a regression even
when every test passes. `TestParsingDoesNotAllocate` holds the zero.

## What the manifest declares, and who reads it

`arandu.mod.toml` is a promise, and the check that gives it weight runs here:
`TestTheDeclaredCapabilitiesAreWhatTheCodeDoes`, in
`tests/Unit/structure_test.go`, reads the code as syntax and compares it with
the four permissions. `network = true` because the package listens;
`filesystem = true` because `CertReloader` reads the certificate files. A new
capability is a change to the manifest in the same commit.

## Adding a dependency

Do not. The module imports the standard library and requires nothing, and the
structure test refuses any other import and any `require` line. If a need seems
to call for one, the need is a missing function of the standard library or a
small file here.

## Publishing

A published Go module version is **immutable**. The proxy serves it forever,
and a mistake is corrected by another release, never by moving a tag.

The repository is created in the `hyz-is` organization from the template, so
its first commit is the template's; the work done here is rebased onto it
before the first tag. Nothing is pushed, created or tagged without the owner's
word.

Before tagging:

- the four gates pass with `GOWORK=off`, and the fuzzers have run on what
  changed;
- `arandu.mod.toml` matches the code;
- `CHANGELOG.md` has the entry under the version, in the Keep a Changelog
  sections, and `UPGRADE.md` has a `## vX.Y.Z` heading for the same version;
- the numbers in the README are from a run of this version.

While the version starts with `v0.`, breaking is allowed. Breaking *quietly* is
not: CI fails unless `UPGRADE.md` names each removal. Four changes break an
installer without touching a signature, and each is worth a line in the
changelog:

- **A default.** Raising a limit lets in what an application did not expect;
  lowering one refuses what it used to take.
- **What a command answers.** A reply code or an enhanced status code is part of
  the protocol an installer's clients depend on.
- **What a `Session` method is called with, and when.** `Reset` after a message,
  `Rcpt` per recipient, the reuse of `MailOptions` and `RcptOptions`.
- **What the EHLO reply offers.** An extension removed breaks the clients that
  use it.
