# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additive, evidence-gated discovery. Never change primary scanner findings.

Alpine: the installed package must predate a fix in that release's own secdb.
Source: OSV must match the exact recorded commit and repository. Distribution
versions, guessed CPEs and fuzzy upstream version matches are not source proof.
Failures and unsupported provenance are recorded separately, never as findings.
"""
import copy
import hashlib
import json
import logging
import re
import time
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import requests
from diskcache import Lock
from univers.versions import AlpineLinuxVersion
from packaging.version import Version

log = logging.getLogger("scan")
CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
TTL = 8 * 3600
MISS = object()


def identities(v):
    return {s for s in [v.get("id"), *v.get("aliases", []), *v.get("upstream", [])]
            if isinstance(s, str) and s}


def purl_for(pkg):
    refs = [r.get("referenceLocator", "") for r in pkg.get("externalRefs", [])
            if r.get("referenceType") == "purl"]
    # Conflicting identities cannot establish provenance.
    return refs[0] if len(set(refs)) == 1 else ""


def source_built(pkg):
    text = " ".join(str(pkg.get(k) or "") for k in ("description", "summary", "sourceInfo", "comment")).lower()
    return "built from source" in text or "source-built" in text


def patch_uncertain(pkg):
    text = " ".join(str(pkg.get(k) or "") for k in ("sourceInfo", "comment", "description")).lower()
    return bool(re.search(r"\b(patched|patches|backport\w*|dirty|modified)\b", text))


def repo_url(value):
    """Canonical comparison only. These URLs are never fetched."""
    value = value.removeprefix("git+")
    u = urlsplit(value)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.port:
        return None
    path = u.path.rstrip("/").removesuffix(".git")
    if not path or any(x in path.split("/") for x in (".", "..")):
        return None
    return "https://" + u.hostname.lower() + path


def exact_source(pkg):
    purl = purl_for(pkg)
    # An APK/RPM/DEB package can carry backports absent from the upstream commit.
    if not purl or purl.startswith(("pkg:apk/", "pkg:deb/", "pkg:rpm/")) or patch_uncertain(pkg):
        return None
    raw, _, qualifiers = purl.partition("?")
    raw = raw.split("#", 1)[0]
    if "@" not in raw:
        return None
    path, revision = raw.rsplit("@", 1)
    if not SHA.fullmatch(revision) or pkg.get("versionInfo") != revision:
        return None
    if path.startswith("pkg:github/"):
        bits = path.removeprefix("pkg:github/").split("/")
        if len(bits) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", b) for b in bits):
            return None
        repo = "https://github.com/" + "/".join(bits)
    elif path.startswith("pkg:generic/"):
        vcs = parse_qs(qualifiers).get("vcs_url", [])
        if len(vcs) != 1:
            return None
        vcs = vcs[0]
        if "@" in vcs:
            vcs, pin = vcs.rsplit("@", 1)
            if pin != revision:
                return None
        repo = repo_url(vcs)
    else:
        return None
    return (repo, revision) if repo else None


def releases_by_container(packages):
    found = {}
    for p in packages:
        if p.get("name") != "alpine-release":
            continue
        v = re.fullmatch(r"(\d+\.\d+)\.\d+(?:-r\d+)?", str(p.get("versionInfo") or ""))
        if v:
            found.setdefault(p.get("packageFileName") or "", set()).add("v" + v[1])
    return {k: next(iter(v)) for k, v in found.items() if len(v) == 1}


def alpine_identity(pkg, releases):
    purl = purl_for(pkg)
    if not purl.startswith("pkg:apk/alpine/") or source_built(pkg) or patch_uncertain(pkg):
        return None
    raw, _, query = purl.partition("?")
    raw = raw.split("#", 1)[0]
    if "@" not in raw:
        return None
    path, version = raw.rsplit("@", 1)
    version = unquote(version)
    # Official Alpine binaries have an APK revision. EVE's source registrations
    # intentionally have none, even though they also receive APK purls.
    if version != pkg.get("versionInfo") or not re.fullmatch(r"[0-9][A-Za-z0-9._+]*-r\d+", version):
        return None
    qualifiers = parse_qs(query)
    distro = qualifiers.get("distro", [])
    explicit = None
    if len(distro) == 1:
        match = re.fullmatch(r"alpine-(\d+\.\d+)(?:\.\d+)?", distro[0])
        if match:
            explicit = "v" + match[1]
        elif not distro[0].startswith("busybox-"):
            return None
    elif distro:
        return None
    container_release = releases.get(pkg.get("packageFileName") or "")
    if explicit and container_release and explicit != container_release:
        return None
    release = explicit or container_release
    if not release:
        return None  # Never use the whole-image Alpine guess for mixed containers.
    origin = qualifiers.get("upstream", [])
    if len(origin) > 1:
        return None
    name = (origin[0].split("@", 1)[0] if origin else unquote(path.rsplit("/", 1)[-1]))
    if not re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", name):
        return None
    return release, name, version


class EvidenceUnavailable(Exception):
    pass


class EvidenceClient:
    def __init__(self, cache, session=None, sleep=time.sleep):
        self.cache = cache
        self.session = session or requests.Session()
        self.sleep = sleep
        self.failed = set()
        self.release_cache = {}

    def json(self, url, payload=None):
        # All callers use fixed public source hosts. No URLs from the SBOM or
        # advisory are fetched. Failures are not persisted as empty success.
        key = ("fallback-v1", url, json.dumps(payload, sort_keys=True))
        cached = self.cache.get(key, default=MISS)
        if cached is not MISS:
            return cached
        if key in self.failed:
            raise EvidenceUnavailable("lookup already failed during this scan")
        digest = hashlib.sha256(repr(key).encode()).hexdigest()
        with Lock(self.cache, "fallback-lock:" + digest, expire=180):
            cached = self.cache.get(key, default=MISS)
            if cached is not MISS:
                return cached
            for attempt in range(3):
                try:
                    if payload is None:
                        r = self.session.get(url, timeout=(5, 20), allow_redirects=False)
                    else:
                        r = self.session.post(url, json=payload, timeout=(5, 20), allow_redirects=False)
                    if r.status_code == 200:
                        data = r.json()
                        if not isinstance(data, dict):
                            raise ValueError("expected JSON object")
                        self.cache.set(key, data, expire=TTL)
                        return data
                    if r.status_code not in (408, 429, 500, 502, 503, 504):
                        break
                except (requests.RequestException, ValueError):
                    pass
                if attempt < 2:
                    self.sleep(2 ** attempt)
            self.failed.add(key)
            raise EvidenceUnavailable("advisory lookup failed; coverage unresolved")

    def secdb(self, release):
        if release in self.release_cache:
            return self.release_cache[release]
        packages = {}
        for repo in ("main", "community"):
            data = self.json(f"https://secdb.alpinelinux.org/{release}/{repo}.json")
            if data.get("distroversion") != release or not isinstance(data.get("packages"), list):
                raise EvidenceUnavailable("Alpine feed release or schema mismatch")
            for row in data["packages"]:
                p = row.get("pkg", {})
                if not isinstance(p.get("name"), str) or not isinstance(p.get("secfixes"), dict):
                    raise EvidenceUnavailable("invalid Alpine package record")
                # Conflicting data is ambiguous; never combine unrelated tracks.
                if p["name"] in packages and packages[p["name"]]["secfixes"] != p["secfixes"]:
                    raise EvidenceUnavailable("conflicting Alpine package records")
                packages[p["name"]] = p
        self.release_cache[release] = packages
        return packages

    def commit(self, repo, revision):
        items, token, seen = [], None, set()
        for _ in range(100):
            query = {"commit": revision}
            if token:
                query["page_token"] = token
            data = self.json("https://api.osv.dev/v1/query", query)
            page = data.get("vulns", [])
            if not isinstance(page, list) or not all(isinstance(v, dict) for v in page):
                raise EvidenceUnavailable("invalid OSV commit response")
            items.extend(page)
            token = data.get("next_page_token")
            if not token:
                return [v for v in items if any(
                    r.get("type") == "GIT" and repo_url(r.get("repo", "")) == repo
                    for a in v.get("affected", []) for r in a.get("ranges", []))]
            if not isinstance(token, str) or token in seen:
                raise EvidenceUnavailable("OSV pagination did not complete")
            seen.add(token)
        raise EvidenceUnavailable("OSV pagination limit exceeded")

    def advisory(self, cve):
        # CVE CNA metadata is enrichment only; it cannot establish affectedness
        # of a distribution package. Alpine's own fixed revision does that.
        data = self.json("https://cveawg.mitre.org/api/cve/" + cve)
        if data.get("cveMetadata", {}).get("cveId") != cve:
            raise EvidenceUnavailable("CVE metadata identity mismatch")
        if data.get("cveMetadata", {}).get("state") != "PUBLISHED":
            raise EvidenceUnavailable("CVE is not published")
        return data


def numeric_version(value):
    # Only compare the common numeric release format. Vendor-specific ordering
    # is not guessed (OpenSSL letter releases, epochs, prereleases, etc.).
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise ValueError("unsupported upstream version format")
    return Version(value)


def cna_confirms_affected(data, origin, installed):
    """Require positive upstream version evidence as well as the distro fix.

    A secdb fixed version alone cannot establish when a flaw was introduced.
    Explicit unaffected entries win; ambiguous conditions never promote.
    """
    version = installed.rsplit("-r", 1)[0]
    current = numeric_version(version)
    positive = False
    for product in data.get("containers", {}).get("cna", {}).get("affected", []):
        if str(product.get("product", "")).lower() != origin.lower():
            continue
        if product.get("platforms") and not all(str(p).lower() in ("linux", "all", "*") for p in product["platforms"]):
            raise ValueError("platform-specific upstream applicability is unresolved")
        if product.get("modules") or product.get("programFiles") or product.get("programRoutines"):
            raise ValueError("component-specific upstream applicability is unresolved")
        versions = product.get("versions", [])
        if not isinstance(versions, list):
            raise ValueError("invalid upstream version records")
        for entry in versions:
            if entry.get("changes"):
                raise ValueError("upstream status transitions need verification")
            start = entry.get("version")
            upper = entry.get("lessThan")
            inclusive = entry.get("lessThanOrEqual")
            if upper is not None and inclusive is not None:
                raise ValueError("ambiguous upstream version bounds")
            if upper is None and inclusive is None:
                match = start == version or start == "*"
            else:
                if entry.get("versionType") not in ("semver", "custom"):
                    raise ValueError("unsupported upstream version ordering")
                match = (start == "*" or current >= numeric_version(start))
                if upper is not None and upper != "*":
                    match = match and current < numeric_version(upper)
                if inclusive is not None and inclusive != "*":
                    match = match and current <= numeric_version(inclusive)
            if match:
                if entry.get("status") != "affected":
                    return False  # An explicit not-affected/unknown status wins.
                positive = True
    return positive


def alpine_candidates(pkg, client, identity, seen):
    release, origin, installed = identity
    record = client.secdb(release).get(origin)
    if record is None:
        return [], "unresolved", "package absent from release security feed"
    try:
        current = AlpineLinuxVersion(installed)
        # Select the earliest fix in this release. Later mentions of the same
        # CVE must not reintroduce it after an earlier backport already fixed it.
        fixes = {}
        for version, cves in record["secfixes"].items():
            if not isinstance(cves, list):
                raise ValueError("invalid CVE list")
            fixed = AlpineLinuxVersion(version)
            for cve in cves:
                # Composite CVE/GHSA strings need explicit parsing upstream;
                # declining them is safer than fuzzy identity matching.
                if isinstance(cve, str) and CVE.fullmatch(cve):
                    if cve not in fixes or fixed < fixes[cve][0]:
                        fixes[cve] = (fixed, version)
        candidates = [(cve, v) for cve, (fixed, v) in fixes.items() if current < fixed and cve not in seen]
    except (ValueError, TypeError):
        return [], "unresolved", "unsupported Alpine fix version or record"
    out = []
    unresolved = []
    for cve, fixed in sorted(candidates):
        try:
            data = client.advisory(cve)
            if pkg.get("name") != origin:
                raise ValueError("binary subpackage applicability needs verification")
            if not cna_confirms_affected(data, origin, installed):
                raise ValueError("upstream affected-version evidence is absent or excludes this version")
        except (EvidenceUnavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
            unresolved.append(cve + ": " + str(exc))
            continue
        cna = data.get("containers", {}).get("cna", {})
        meta = data["cveMetadata"]
        details = next((x.get("value", "") for x in cna.get("descriptions", []) if x.get("lang", "").startswith("en")), "")
        proof = (f"Additive fallback: Alpine {release}, source package {origin}. "
                 "The scanner verified both Alpine package revision and CNA upstream affected-version evidence for the detected package. "
                 f"Evidence: https://secdb.alpinelinux.org/{release}/main.json and "
                 f"https://secdb.alpinelinux.org/{release}/community.json. "
                 "This is a package advisory match; runtime reachability is not established.")
        severity = []
        for metric in cna.get("metrics", []):
            for key, kind in (("cvssV4_0", "CVSS_V4"), ("cvssV3_1", "CVSS_V3"), ("cvssV3_0", "CVSS_V3")):
                vector = metric.get(key, {}).get("vectorString")
                if isinstance(vector, str):
                    severity.append({"type": kind, "score": vector})
        out.append({"id": cve, "aliases": [], "upstream": [],
                    "summary": cna.get("title") or details.split("\n")[0][:300] or cve,
                    "details": details + "\n\n" + proof,
                    "published": meta.get("datePublished", ""), "modified": meta.get("dateUpdated", ""),
                    "severity": severity,
                    "affected": [{"package": {"name": origin, "ecosystem": "Alpine:" + release},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
                    "database_specific": {"cvewatch_fallback": {"source": "alpine-secdb", "release": release,
                                                                  "origin": origin, "installed": installed, "fixed": fixed}}})
    if unresolved:
        return out, "unresolved", "; ".join(unresolved)
    return out, "checked", "Alpine fixed revisions and upstream affected versions checked"


def additive_pass(packages, primary, cache, cvss_data, client=None):
    """Return (additions, audit), leaving primary and package inputs untouched."""
    client = client or EvidenceClient(cache)
    releases = releases_by_container(packages)
    existing = {}
    for row in primary:
        existing.setdefault(package_key(row["package"]), set()).update(
            alias for v in row["vulnerabilities"] for alias in identities(v))
    additions, records = [], []
    for pkg in packages:
        key = package_key(pkg)
        seen = existing.get(key, set())
        record = {"package": pkg.get("name"), "version": pkg.get("versionInfo"),
                  "container": pkg.get("packageFileName"), "added": []}
        try:
            alpine = alpine_identity(pkg, releases)
            source = exact_source(pkg)
            if alpine:
                candidates, status, reason = alpine_candidates(pkg, client, alpine, seen)
                record.update(status=status, reason=reason, source="alpine-secdb")
            elif source:
                candidates = copy.deepcopy(client.commit(*source))
                record.update(status="checked", reason="exact commit and repository queried; empty response does not prove coverage", source="osv-git")
                for v in candidates:
                    v["details"] = (v.get("details") or "") + f"\n\nAdditive fallback: OSV matches exact source commit {source[1]} in {source[0]}. Runtime reachability is not established."
            else:
                candidates = []
                record.update(status="unresolved", reason="no verified distro release/revision or exact unpatched source commit")
            accepted = []
            for v in candidates:
                ids = identities(v)
                if v.get("withdrawn") or not v.get("id") or ids & seen:
                    continue
                # Suppress duplicates across fallback providers and records too.
                seen = seen | ids
                v["exploitability"] = [cvss_data[c.lower()] for c in sorted(ids) if c.lower() in cvss_data]
                accepted.append(v)
                record["added"].append(v["id"])
            if accepted:
                additions.append({"package": copy.deepcopy(pkg), "vulnerabilities": accepted})
                existing[key] = seen
        except (EvidenceUnavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
            record.update(status="unresolved", reason=str(exc), added=[])
            log.warning("Fallback unresolved for %s: %s", pkg.get("name"), exc)
        records.append(record)
    counts = dict(Counter(r["status"] for r in records))
    audit = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
             "input_sha256": hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest(),
             "counts": counts, "added_findings": sum(len(r["added"]) for r in records), "packages": records}
    return additions, audit


def package_key(pkg):
    return (pkg.get("SPDXID"), pkg.get("name"), pkg.get("versionInfo"), pkg.get("packageFileName"), purl_for(pkg))


def run_additive(packages, primary, cache, cvss_data, output_file):
    additions, audit = additive_pass(packages, primary, cache, cvss_data)
    # Persist coverage outside the per-cycle directory, which cleanup removes.
    path = Path(cache.directory).parent / "fallback-reports" / (Path(output_file).name + ".coverage.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Concurrent scans may share a cache and output label. Each writer owns
    # its staging file; readers see one complete report after atomic replace.
    fd, temp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(audit, out, indent=2)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    log.info("Additive fallback: %d findings; coverage %s; report %s", audit["added_findings"], audit["counts"], path)
    return additions
