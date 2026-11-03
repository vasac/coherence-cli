#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
"""Create a new draft, upload and verify its seven assets, then publish it.

Use only the pinned RELEASE_GH setup output. Never reuse or delete a release.
The workflow must run the read-only preflight immediately before this helper.
See scripts/RELEASING.md for compatibility, failure states and recovery.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

SCRIPTS = Path(__file__).resolve().parent
STAGING = runpy.run_path(str(SCRIPTS / "stage-release-assets.py"))
PREFLIGHT = runpy.run_path(str(SCRIPTS / "preflight-release.py"))


class PublicationError(Exception):
    """Publication cannot safely continue."""

    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


def require(condition, message):
    if not condition:
        raise PublicationError(message)


def required_env(name):
    value = os.environ.get(name, "")
    require(bool(value) and "\n" not in value and "\r" not in value,
            f"{name} must be set to a single-line value.")
    return value


def asset_types(version):
    # Preserve the existing explicit MIME values, including Linux amd64.
    # gh 2.103.3 release upload infers MIME from extensions and cannot set it:
    # https://github.com/cli/cli/blob/v2.103.3/pkg/cmd/release/shared/upload.go
    return {
        f"cohctl-{version}-linux-amd64": "application/x-mach-binary",
        f"cohctl-{version}-linux-arm64": "application/x-executable",
        f"cohctl-{version}-linux-386": "application/x-executable",
        f"cohctl-{version}-windows-amd64.exe": "application/x-dosexec",
        f"cohctl-{version}-windows-arm64.exe": "application/x-dosexec",
        "docs.zip": "application/zip",
        f"cohctl-{version}-checksums.txt": "text/plain",
    }


def staged_assets(directory, version):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(),
            "RELEASE_ASSETS must be the absolute staged directory.")
    types = asset_types(version)
    require({path.name for path in directory.iterdir()} == types.keys(),
            "Staged directory must contain exactly the seven release assets.")
    for name in types:
        STAGING["regular_file"](directory / name)
    manifest = f"cohctl-{version}-checksums.txt"
    data = (directory / manifest).read_bytes()
    hashes = STAGING["parse_manifest"](data, types.keys() - {manifest})
    hashes[manifest] = hashlib.sha256(data).hexdigest()
    assets = {}
    for name, mime in types.items():
        path = directory / name
        require(STAGING["sha256"](path) == hashes[name], f"Staged SHA-256 mismatch: {name}")
        assets[name] = {"path": path, "mime": mime, "sha256": hashes[name], "size": path.stat().st_size}
    return assets


class Publisher:
    def __init__(self, gh, repository, version, sha, env, temporary):
        self.gh, self.repository, self.version, self.sha = gh, repository, version, sha
        self.env, self.temporary = env, temporary
        self.prefix = f"repos/{repository}"
        self.identity = None
        self.phase = "input validation"
        self.write_started = False

    def command(self, arguments, output=None):
        # Never echo CLI stderr, response bodies or the inherited environment.
        # Writes run once. A failure or timeout may still have changed GitHub.
        result = subprocess.run([self.gh, *arguments], env=self.env, stdin=subprocess.DEVNULL,
                                stdout=output if output is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=600)
        require(result.returncode >= 0, "CLI terminated by a signal.")
        if result.returncode:
            raise PublicationError(f"CLI failed during {self.phase} (exit {result.returncode}).",
                                   result.returncode)
        return result.stdout

    def api(self, method, endpoint, extra=(), output=None, accept="application/vnd.github+json"):
        result = self.command(["api", "--hostname", "github.com", "--method", method,
                               "--header", f"Accept: {accept}",
                               "--header", "X-GitHub-Api-Version: 2022-11-28", *extra, endpoint], output)
        if output is None:
            try:
                return json.loads(result)
            except (ValueError, UnicodeError) as error:
                raise PublicationError(f"Malformed API response during {self.phase}.") from error
        return None

    def release_metadata(self, release, draft):
        require(isinstance(release, dict), "Malformed release metadata.")
        identity = release.get("id")
        require(type(identity) is int and identity > 0, "Malformed release ID.")
        require(self.identity is None or identity == self.identity, "Release ID changed.")
        require(release.get("url") == f"https://api.github.com/{self.prefix}/releases/{identity}"
                and release.get("upload_url") ==
                f"https://uploads.github.com/{self.prefix}/releases/{identity}/assets{{?name,label}}",
                "Release destination does not match the workflow repository.")
        require(release.get("tag_name") == self.version
                and release.get("target_commitish") == self.sha
                and release.get("name") == f"Coherence CLI - {self.version}"
                and release.get("body") == f"Coherence CLI Release {self.version}"
                and release.get("draft") is draft and release.get("prerelease") is False,
                "Release metadata does not match the expected release state.")
        return identity

    def asset_metadata(self, asset, name, expected):
        require(isinstance(asset, dict), "Malformed asset metadata.")
        identity = asset.get("id")
        require(type(identity) is int and identity > 0, "Malformed asset ID.")
        require(asset.get("url") == f"https://api.github.com/{self.prefix}/releases/assets/{identity}"
                and asset.get("name") == name and asset.get("label") in (None, "")
                and asset.get("state") == "uploaded"
                and type(asset.get("size")) is int and asset["size"] == expected["size"]
                and asset.get("content_type") == expected["mime"],
                f"Asset metadata mismatch: {name}")
        # Some API responses omit the digest. Always verify downloaded bytes too.
        require(asset.get("digest") in (None, "sha256:" + expected["sha256"]),
                f"Asset digest mismatch: {name}")
        return identity

    def list_assets(self):
        pages = self.api("GET", f"{self.prefix}/releases/{self.identity}/assets?per_page=100",
                         ("--paginate", "--slurp"))
        require(isinstance(pages, list) and bool(pages) and all(isinstance(p, list) for p in pages),
                "Malformed paginated asset list.")
        return [asset for page in pages for asset in page]

    def validate(self, assets, uploaded, draft=True):
        self.release_metadata(self.api("GET", f"{self.prefix}/releases/{self.identity}"), draft)
        remote = self.list_assets()
        require(len(remote) == len(assets), "Unexpected release asset count.")
        seen = set()
        for asset in remote:
            require(isinstance(asset, dict), "Malformed asset list entry.")
            name = asset.get("name")
            require(isinstance(name, str) and name in assets and name not in seen,
                    "Unexpected or duplicate release asset name.")
            seen.add(name)
            require(self.asset_metadata(asset, name, assets[name]) == uploaded[name], "Asset ID changed.")

    def identify_created_draft(self, created_url):
        # A successful creation need not be visible in the next list snapshot.
        # Repeat only this read, and only when neither the tag nor the returned
        # URL is present. Conflicts, API failures and malformed data still stop.
        delays = (0, 1, 2, 4, 8)
        for attempt, delay in enumerate(delays, 1):
            if delay:
                time.sleep(delay)
            pages = self.api("GET", f"{self.prefix}/releases?per_page=100", ("--paginate", "--slurp"))
            require(isinstance(pages, list) and bool(pages) and all(isinstance(p, list) for p in pages)
                    and all(isinstance(r, dict)
                            and type(r.get("id")) is int and r["id"] > 0
                            and isinstance(r.get("tag_name"), str) and bool(r["tag_name"])
                            and isinstance(r.get("html_url"), str) and bool(r["html_url"])
                            and type(r.get("draft")) is bool for p in pages for r in p),
                    "Malformed release list.")
            releases = [r for page in pages for r in page]
            matches = [r for r in releases if r.get("tag_name") == self.version]
            url_matches = [r for r in releases if r.get("html_url") == created_url]
            # Counts distinguish missing visibility from conflicting identity
            # without logging response bodies, credentials or release notes.
            print(f"Created draft lookup: attempt={attempt}/{len(delays)} pages={len(pages)} "
                  f"releases={len(releases)} tag_matches={len(matches)} url_matches={len(url_matches)}.",
                  flush=True)
            if matches or url_matches:
                require(len(matches) == 1 and len(url_matches) == 1
                        and matches[0].get("html_url") == created_url,
                        "Cannot identify the draft returned by creation; no further writes are allowed.")
                return matches[0]
        raise PublicationError("Created draft is not visible after five release-list reads; "
                               "no further writes are allowed.")

    def publish(self, assets, ref):
        # Repeat the read-only identity/absence snapshot after local input checks.
        # This is not an atomic lock. --verify-tag also checks at creation time.
        self.phase = "release identity and absence validation"
        PREFLIGHT["check_release"](self.gh, self.repository, ref, self.sha, self.env)
        self.phase = "draft creation"
        print(f"Starting draft creation: repository={self.repository} tag={self.version} commit={self.sha}.",
              flush=True)
        self.write_started = True
        created_url = self.command([
            "release", "create", self.version, "--repo", f"github.com/{self.repository}",
            "--verify-tag", "--draft", "--prerelease=false", "--target", self.sha,
            "--title", f"Coherence CLI - {self.version}",
            "--notes", f"Coherence CLI Release {self.version}"]).decode("utf-8").strip()
        # gh create prints the new release URL. Bind the following reads/writes
        # to that exact response and ID; never resume a draft found only by tag.
        require(created_url.startswith(f"https://github.com/{self.repository}/releases/tag/")
                and re.fullmatch(r"https://github.com/[A-Za-z0-9/._-]+", created_url) is not None,
                "Creation did not return a valid release URL.")
        print(f"Draft creation returned: {created_url}", flush=True)
        self.phase = "created draft identification"
        self.identity = self.release_metadata(self.identify_created_draft(created_url), True)
        print(f"Created draft: repository={self.repository} tag={self.version} release_id={self.identity}.",
              flush=True)
        require(self.list_assets() == [], "New draft already has assets; refusing to reuse or replace them.")
        uploaded = {}
        for name, expected in assets.items():
            self.phase = f"upload of {name}"
            require(STAGING["sha256"](expected["path"]) == expected["sha256"], "Staged bytes changed.")
            asset = self.api(
                "POST", f"https://uploads.github.com/{self.prefix}/releases/{self.identity}/assets"
                f"?name={quote(name, safe='')}",
                ("--header", f"Content-Type: {expected['mime']}", "--input", str(expected["path"])))
            identity = self.asset_metadata(asset, name, expected)
            require(identity not in uploaded.values(), "Duplicate uploaded asset ID.")
            uploaded[name] = identity
            print(f"Uploaded asset: release_id={self.identity} asset_id={identity} name={name}.", flush=True)
        self.phase = "draft validation"
        self.validate(assets, uploaded)
        for name, expected in assets.items():
            # Redirect faithful binary output to a file, never to a terminal.
            # --allow-escape-sequences is needed for arbitrary binary bytes in
            # gh 2.103.3 (pkg/cmd/api/api.go processResponse).
            download = self.temporary / "asset-download"
            with download.open("wb") as output:
                self.api("GET", f"{self.prefix}/releases/assets/{uploaded[name]}",
                         ("--allow-escape-sequences",), output, "application/octet-stream")
            require(STAGING["sha256"](download) == expected["sha256"], f"Draft download mismatch: {name}")
            download.unlink()
        # Recheck metadata after the downloads and before the publication write.
        self.validate(assets, uploaded)
        self.phase = "publication"
        print(f"Publishing validated draft: release_id={self.identity}.", flush=True)
        release = self.api("PATCH", f"{self.prefix}/releases/{self.identity}", ("--field", "draft=false"))
        self.release_metadata(release, False)
        self.phase = "published release validation"
        self.validate(assets, uploaded, draft=False)
        print(f"Release published: repository={self.repository} tag={self.version} release_id={self.identity}.",
              flush=True)


def main():
    gh = required_env("RELEASE_GH")
    require(Path(gh).is_absolute() and Path(gh).is_file() and os.access(gh, os.X_OK),
            "RELEASE_GH must be the absolute executable path from pinned CLI setup.")
    repository = required_env("RELEASE_REPOSITORY")
    require(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository) is not None
            and repository.split("/")[1] not in (".", ".."), "Invalid release repository.")
    version = required_env("RELEASE_VERSION")
    require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version) is not None, "Invalid release version.")
    ref = required_env("RELEASE_REF")
    require(required_env("RELEASE_REF_TYPE") == "tag" and ref == "refs/tags/" + version,
            "Exact tag name must equal the built CLI version.")
    sha = PREFLIGHT["object_sha"](required_env("RELEASE_SHA"))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GH_", "GITHUB_"))}
    require(PREFLIGHT["run"](["git", "rev-parse", "--verify", "HEAD^{commit}"], env).strip() == sha,
            "Checked-out commit does not match the triggering commit.")
    assets = staged_assets(Path(required_env("RELEASE_ASSETS")), version)
    runner = Path(required_env("RUNNER_TEMP"))
    require(runner.is_absolute() and runner.is_dir(), "RUNNER_TEMP must be an absolute existing directory.")
    token = required_env("GH_TOKEN")
    # Discard other tokens, host/API overrides, debug/pager settings and stored
    # configuration. Supply this step's token only to the pinned executable.
    env.update(GH_TOKEN=token, GH_HOST="github.com", GH_PROMPT_DISABLED="1",
               GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_PAGER="cat", PAGER="cat")
    with tempfile.TemporaryDirectory(prefix="release-publication-", dir=runner) as temporary:
        temporary = Path(temporary)
        config = temporary / "config"
        config.mkdir()
        env["GH_CONFIG_DIR"] = str(config)
        publisher = Publisher(gh, repository, version, sha, env, temporary)
        try:
            publisher.publish(assets, ref)
        except BaseException:
            if publisher.write_started:
                print(f"Release stopped during {publisher.phase}: repository={repository} tag={version} "
                      f"commit={sha} release_id={publisher.identity or 'unknown'}. "
                      "A write may have succeeded. No write retry, reuse or deletion was attempted. "
                      "Inspect the run and remote state before approved recovery; see scripts/RELEASING.md.",
                      file=sys.stderr)
            raise


if __name__ == "__main__":
    try:
        main()
    except (PublicationError, PREFLIGHT["PreflightError"], STAGING["StagingError"],
            OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        # Exception text from subprocess timeouts includes command arguments;
        # report a fixed message instead. CLI stderr is never exposed.
        message = "CLI operation timed out." if isinstance(error, subprocess.TimeoutExpired) else str(error)
        print(f"Release publication failed: {message}", file=sys.stderr)
        sys.exit(getattr(error, "status", 1))
