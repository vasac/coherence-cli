#!/usr/bin/env python3
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
"""Read-only, fail-closed release gate. Workflow context is supplied through env."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote


class PreflightError(Exception):
    """A release identity or lookup could not be verified."""


def require(condition, message):
    if not condition:
        raise PreflightError(message)


def required_env(name):
    value = os.environ.get(name, "")
    require(bool(value.strip()), f"{name} must be set.")
    return value


def object_sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None,
            "Invalid Git object SHA in release identity.")
    return value


def target(value):
    require(isinstance(value, dict) and value.get("type") in ("commit", "tag"),
            "Remote tag must resolve through tag objects to a commit.")
    return value["type"], object_sha(value.get("sha"))


def run(command, env=None):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
    require(result.returncode == 0,
            f"Read-only command failed (exit {result.returncode}); release validation stopped.")
    return result.stdout


def check_release(gh, repository, ref, sha, env):
    prefix = f"repos/{repository}"

    def api(endpoint, paginate=False):
        command = [gh, "api", "--hostname", "github.com", "--method", "GET",
                   "--header", "Accept: application/vnd.github+json",
                   "--header", "X-GitHub-Api-Version: 2022-11-28"]
        if paginate:
            command += ["--paginate", "--slurp"]
        try:
            return json.loads(run(command + [endpoint], env))
        except (ValueError, UnicodeError) as error:
            raise PreflightError("Malformed GitHub API response; release validation stopped.") from error

    # A public, read-only listing can silently omit drafts. Require push access
    # before relying on the release list, using the same token for every lookup.
    repo = api(prefix)
    require(isinstance(repo, dict)
            and isinstance(repo.get("full_name"), str)
            and repo["full_name"].lower() == repository.lower(),
            "GitHub API returned a different or malformed repository identity.")
    permissions = repo.get("permissions")
    require(isinstance(permissions, dict) and permissions.get("push") is True,
            "Cannot verify repository push access required to see draft releases.")

    remote = api(f"{prefix}/git/ref/tags/{quote(ref[len('refs/tags/'):], safe='')}")
    require(isinstance(remote, dict) and remote.get("ref") == ref,
            "Remote tag reference is missing or does not match the triggering tag.")
    kind, resolved = target(remote.get("object"))
    seen = set()
    while kind == "tag":
        require(resolved not in seen and len(seen) < 32,
                "Remote annotated tag chain is cyclic or too deep to resolve.")
        seen.add(resolved)
        tag = api(f"{prefix}/git/tags/{resolved}")
        require(isinstance(tag, dict) and tag.get("sha") == resolved,
                "Malformed annotated tag identity.")
        kind, resolved = target(tag.get("object"))
    require(resolved == sha, "Remote tag commit does not match the triggering/checked-out commit.")

    # Do not use the published-only releases/tags endpoint or infer absence from
    # a failed command. gh 2.103.3 follows Link pagination and slurps each page.
    pages = api(f"{prefix}/releases?per_page=100", paginate=True)
    require(isinstance(pages, list) and bool(pages), "Malformed paginated release list.")
    tag_name = ref[len("refs/tags/"):]
    for page in pages:
        require(isinstance(page, list), "Malformed release-list page.")
        for release in page:
            require(isinstance(release, dict)
                    and type(release.get("id")) is int and release["id"] > 0
                    and isinstance(release.get("tag_name"), str) and bool(release["tag_name"])
                    and type(release.get("draft")) is bool,
                    "Malformed release identity in release list.")
            require(release["tag_name"] != tag_name,
                    "A release already exists for the exact tag (including drafts).")


def main():
    gh = required_env("RELEASE_GH")
    require(Path(gh).is_absolute() and Path(gh).is_file() and os.access(gh, os.X_OK),
            "RELEASE_GH must be the absolute executable path from pinned CLI setup.")
    repository = required_env("RELEASE_REPOSITORY")
    require(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository) is not None
            and repository.split("/")[1] not in (".", ".."), "Invalid release repository.")
    ref = required_env("RELEASE_REF")
    require(required_env("RELEASE_REF_TYPE") == "tag" and ref.startswith("refs/tags/"),
            "Release workflow must be triggered by a tag reference.")
    require(ref == "refs/tags/" + required_env("RELEASE_VERSION"),
            "Exact tag name must equal the built CLI version.")
    sha = object_sha(required_env("RELEASE_SHA"))
    required_env("GH_TOKEN")
    # Git validates the literal ref as an argument, never as executable text.
    run(["git", "check-ref-format", ref])
    checkout = object_sha(run(["git", "rev-parse", "--verify", "HEAD^{commit}"]).strip())
    require(checkout == sha, "Checked-out commit does not match the triggering commit.")

    # Ignore stored CLI credentials, host mappings, debugging and other token
    # sources. The workflow gives only this step GH_TOKEN; nothing is persisted.
    env = dict(os.environ)
    for key in ("GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_DEBUG"):
        env.pop(key, None)
    env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
               GH_NO_EXTENSION_UPDATE_NOTIFIER="1")
    with tempfile.TemporaryDirectory(prefix="release-preflight-", dir=os.environ.get("RUNNER_TEMP")) as config:
        env["GH_CONFIG_DIR"] = config
        check_release(gh, repository, ref, sha, env)
    print(f"Release preflight passed for {repository} {ref} at {sha}.")
    # This is a snapshot, not an atomic lock against external actors. A future
    # gh release create replacement must also use --verify-tag at creation time.


if __name__ == "__main__":
    try:
        main()
    except (PreflightError, OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        print(f"Release preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
