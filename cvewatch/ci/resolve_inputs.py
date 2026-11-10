#!/usr/bin/env python3
"""Resolve PR identity before any untrusted EVE code runs.

workflow_run has no event.pull_request. Query its associated PR and reject stale
runs rather than scanning a newer head against metadata from an older build.
"""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class InputError(ValueError):
    pass


def fetch_pr(repository, number):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise InputError("Invalid caller repository")
    if not isinstance(number, int) or number < 1:
        raise InputError("Invalid PR number")
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/pulls/{number}", headers=headers)
    # GitHub repository renames should not redirect a credentialed request.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        return json.load(response)


def resolve(event, inputs, repository, get_pr=fetch_pr):
    pr = event.get("pull_request") or {}
    run = event.get("workflow_run")
    if run and not all(inputs.get(k) for k in ("repo", "revision", "base_repo", "base_ref")):
        associated = run.get("pull_requests") or []
        if len(associated) != 1:
            raise InputError("workflow_run needs exactly one associated PR, or all four explicit scan inputs")
        pr = get_pr(repository, associated[0]["number"])
        if pr.get("head", {}).get("sha") != run.get("head_sha"):
            raise InputError("PR head changed since this workflow run; scan the latest PR event instead")
    head, base = pr.get("head") or {}, pr.get("base") or {}
    values = {
        "repo": inputs.get("repo") or (head.get("repo") or {}).get("clone_url"),
        "revision": inputs.get("revision") or head.get("sha"),
        "base_repo": inputs.get("base_repo") or (base.get("repo") or {}).get("clone_url") or "https://github.com/lf-edge/eve.git",
        "base_ref": inputs.get("base_ref") or base.get("ref") or "master",
    }
    for key, value in values.items():
        if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise InputError(f"Missing or invalid {key}")
        if value.startswith("-"):
            raise InputError(f"Option-like {key} is not allowed")
    for key in ("repo", "base_repo"):
        url = urlsplit(values[key])
        if url.scheme != "https" or url.hostname != "github.com" or url.username or url.password or url.port or url.query or url.fragment:
            raise InputError(f"{key} must be an HTTPS GitHub repository URL")
        if not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url.path):
            raise InputError(f"Invalid repository path in {key}")
    return values


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    names = {"repo": "INPUT_REPO", "revision": "INPUT_REVISION", "base_repo": "INPUT_BASE_REPO", "base_ref": "INPUT_BASE_REF"}
    result = resolve(event, {k: os.environ.get(v, "") for k, v in names.items()}, os.environ.get("GITHUB_REPOSITORY", ""))
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for key, value in result.items():
            out.write(f"{key}={value}\n")
    print("Resolved PR revision and upstream baseline")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Cannot resolve scan inputs: {exc}", file=sys.stderr)
        raise SystemExit(2)
