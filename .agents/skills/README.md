# Skills

Procedures an assistant follows when working on this package.

They live in `.agents/skills/<name>/SKILL.md`, which is the path the coding
assistants read from. It is one directory rather than a file per vendor, so a
skill written once is read by whatever this package is being written with.

Each file opens with frontmatter carrying a `name` and a `description`. The
`name` has to equal the directory name exactly, or the skill is not loaded. The
description is what a tool reads to decide whether the skill is relevant, so it
names the situation you are in rather than the topic it covers.

| skill | when it fires |
| --- | --- |
| `smtpd-release` | the gates, the fuzzers, the benchmarks, the manifest, a version, a tag |
| `smtpd-package` | building an SMTP server **in an application** with this package |

The template this package started from carried a `-policy`, a `-module` and a
`-vault-notes` skill. The first two taught the HTTP module the template ships,
which this package removed: there is no policy to open and no route, handler or
migration to add. The third applies only inside a vault that holds notes about
modules, and this checkout is not the place that defines them.

`smtpd-package` has a different audience from the other one, on purpose: it
travels with the package so that an assistant working in somebody else's
project, the one running `go get`, has the wiring and its symptoms in front of
it instead of writing an SMTP server of its own. Its frontmatter says so, under
`metadata`, with `audience: app`. No other skill here carries it: an
application that received the release procedure would follow it.

## Why these exist

The common failure modes when changing this package are a default that accepts
a recipient, a bare line feed taken for a line end, a refusal that leaves the
data of a message to be read as commands, an error detail that reaches the
client, an allocation on the command path, and a dependency. None belongs here.

## Adding your own

A skill in this directory is yours and travels with the repository. Keep it a
procedure rather than a description: a file that says "read the documentation"
never changes what anybody does.
