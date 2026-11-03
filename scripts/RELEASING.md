# Release process

The release workflow runs when a tag is pushed. It requests `contents: write`
for `GITHUB_TOKEN` and serializes runs for the same repository and tag without
cancelling a release in progress.

## Publication sequence

1. Run the release checks and build the binaries and documentation. Derive the
   release version from the built CLI. Use the pinned GitHub CLI after its
   archive checksum and version have been verified during setup.
2. Generate the SHA-256 manifest and stage the seven assets listed below.
   Check their exact names and hashes before publication.
3. Check the workflow repository, triggering tag and checked-out commit.
   Require a valid Git tag ref that exactly matches the supported CLI version.
   Recheck the staged names, regular files
   and hashes before contacting GitHub.
4. Run one remote identity, authority and absence gate immediately before draft
   creation. Verify the repository and resolve the remote tag to the checked
   commit, including nested annotated tags. Prove the token's release write
   authority with
   [`POST /repos/{owner}/{repo}/releases/generate-notes`](https://docs.github.com/en/rest/releases/releases#generate-release-notes-content-for-a-release).
   This request saves no release or tag. Require a successful response with
   string `name` and `body` fields, then discard the generated notes. Read all
   release-list pages and reject any existing release for the tag, including
   drafts. An API error or malformed response fails the check.
   Create one draft with `gh release create --verify-tag`, targeting the checked
   commit with `prerelease=false`, title `Coherence CLI - VERSION` and body
   `Coherence CLI Release VERSION`. Bind subsequent
   writes to the returned URL and matching release ID, and require the new draft
   to have no assets.
5. Upload the seven staged files with explicit names and Content-Type values.
   Check asset IDs, names, sizes, empty labels, states and MIME types. Download
   all draft assets and compare their hashes, including the manifest hash.
   Check the complete asset list and release metadata before and after the draft downloads. Publish by release ID, then check
   the published metadata and complete asset list.
6. Download the public manifest and assets without authentication from the
   workflow repository. Compare the manifest with the generated copy and
   verify every asset checksum. Any failure fails the job.
7. Run the Pages and `stable.txt` step only after successful publication and
   public verification. This step uses `if: ${{ success() }}`.

Authenticated release operations use the absolute GitHub CLI path from setup,
the workflow repository and a temporary isolated CLI configuration. The token
is scoped to the publication step, the sole authenticated entry point
(`publish-release.py`). Staging (`stage-release-assets.py`) uses no token.
Local Git commands run without `GH_` or `GITHUB_` environment variables.
The remote gate is a snapshot, not an atomic lock. `--verify-tag` adds a tag
existence check at creation; it does not make the sequence atomic.

If both the created tag and returned URL are absent from the release list,
the helper allows five reads in total, with waits of 1, 2, 4 and 8 seconds.
Each read checks all pages. Conflicting identities, malformed responses and
API errors stop immediately. Exhausted reads stop before uploads. Creation,
uploads and publication each run once; the helper does not retry writes.

## Release assets

`VERSION` denotes the CLI version and matching tag. The six payloads and manifest
share one Python definition in `release_support.py`; the shell checksum generator
and public verifier remain independent. The manifest has exactly six entries and
never includes itself.

Uploads retain these historical MIME values, including Linux amd64's
`application/x-mach-binary`. They are preserved metadata rather than an essential
download or checksum contract. Explicit API uploads bind each single-attempt write
to the identified release ID.

| Asset | Content-Type |
| --- | --- |
| `cohctl-VERSION-linux-amd64` | `application/x-mach-binary` |
| `cohctl-VERSION-linux-arm64` | `application/x-executable` |
| `cohctl-VERSION-linux-386` | `application/x-executable` |
| `cohctl-VERSION-windows-amd64.exe` | `application/x-dosexec` |
| `cohctl-VERSION-windows-arm64.exe` | `application/x-dosexec` |
| `docs.zip` | `application/zip` |
| `cohctl-VERSION-checksums.txt` | `text/plain` |

## Failure and recovery

The sequence is not atomic. Concurrency serializes workflow runs for the same
repository and tag, but does not prevent external tag or release changes.
A failed request can leave a draft, a partial or `starter` asset, or an
already published release. A public-verification failure leaves the release
public and blocks Pages. Do not infer rollback from a failed command.

Recovery requires a separate review and approval:

1. Keep the job log. Inspect the repository, tag, commit, creation URL, release
   ID and asset IDs with credentials that can see drafts. If the release ID
   is unknown, inspect candidate drafts and their creation times. A tag match
   alone does not prove ownership.
2. Check whether the release is a draft or public. Inspect each asset's state,
   size, MIME type and bytes. For a public release, also inspect public
   downloads and the current `stable.txt` state.
3. Agree on the exact corrective action. The helper cannot resume a draft,
   replace an asset or delete a release. A rerun rejects an existing release,
   including an incomplete draft. Cleanup, manual completion or a fresh run
   needs approval for that exact remote action and current state.
