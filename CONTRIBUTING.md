# Contributing to this repository

We welcome your contributions! There are multiple ways to contribute.

## Opening issues

For bugs or enhancement requests, please file a GitHub issue unless it's
security related. When filing a bug remember that the better written the bug is,
the more likely it is to be fixed. If you think you've found a security
vulnerability, do not raise a GitHub issue and follow the instructions in our
[security policy](./SECURITY.md).

## Contributing code

We welcome your code contributions. Before submitting code via a pull request,
you will need to have signed the [Oracle Contributor Agreement][OCA] (OCA) and
your commits need to include the following line using the name and e-mail
address you used to sign the OCA:

```text
Signed-off-by: Your Name <you@example.org>
```

This can be automatically added to pull requests by committing with `--sign-off`
or `-s`, e.g.

```text
git commit --signoff
```

Only pull requests from committers that can be verified as having signed the OCA
can be accepted.

## Local checks

Use the Go version in `go.mod`. Run these checks before submitting a change:

```bash
make golangci
go test ./pkg/... ./utils/lintbaseline
go vet ./...
```

`make golangci` installs the official GolangCI-Lint **2.15.0** binary in
`build/tools/bin`, checks the exact cached version on every invocation, checks
formatting without rewriting files, and analyzes `./...` including tests. Module
loading is read-only. The build and release workflows run the same target and
propagate failures.

The full report is matched against [the reviewed style baseline](.golangci-baseline.json)
by exact linter, file, message, source and occurrence count. New findings and
stale entries fail. Security and Staticcheck SA correctness findings cannot be
accepted by this baseline. Fix new issues and remove resolved entries. Baseline
or tool-version updates require explicit review with per-entry reasons; do not
automatically regenerate the baseline.

Run `make golangci-full` to see all retained debt. It exits nonzero while that
debt remains. Each baseline entry records the finding, source and reason for
deferral. Review baseline or tool-version changes against that report and rerun
`make golangci` to verify the retained occurrences. For workflow edits, also run
`actionlint` on the changed workflow files.

## Pull request process

1. Ensure there is an issue created to track and discuss the fix or enhancement
   you intend to submit.
1. Fork this repository.
1. Create a branch in your fork to implement the changes. We recommend using
   the issue number as part of your branch name, e.g. `1234-fixes`.
1. Ensure that any documentation is updated with the changes that are required
   by your change.
1. Ensure that any samples are updated if the base image has been changed.
1. Submit the pull request. *Do not leave the pull request blank*. Explain exactly
   what your changes are meant to do and provide simple steps on how to validate.
   your changes. Ensure that you reference the issue you created as well.
1. We will assign the pull request to 2-3 people for review before it is merged.

## Code of conduct

Follow the [Golden Rule](https://en.wikipedia.org/wiki/Golden_Rule). If you'd
like more specific guidelines, see the [Contributor Covenant Code of Conduct][COC].

[OCA]: https://oca.opensource.oracle.com
[COC]: https://www.contributor-covenant.org/version/1/4/code-of-conduct/
