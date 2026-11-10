# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scan SPDX SBOM files for known vulnerabilities using the OSV database.
# Queries the OSV API for each package and caches the results (8h TTL) so
# consecutive runs reuse them.

import requests
import argparse
import copy
import json
import logging
import re
import time
import random
import os
import tempfile
from diskcache import Cache
import csv
import zipfile
from urllib.parse import parse_qs, unquote, urlsplit
from packaging import version as packaging_version

log = logging.getLogger("scan")

# OSV query results are cached for 8h so consecutive scans in one session reuse
# them, but the next day's scan always re-queries — otherwise we'd miss CVEs
# published overnight for a package (the cache must expire well within 24h).
OSV_CACHE_TTL_SECONDS = 8 * 3600

# sentinel to tell a cache miss apart from a cached empty result
_CACHE_MISS = object()


class ScanError(RuntimeError):
    """The scan is incomplete and must not pass a vulnerability gate."""

def extract_package_info(package, alpine_version=None):
    name = package.get("name", "Unknown")
    version = package.get("versionInfo")
    raw = next((r.get("referenceLocator", "") for r in package.get("externalRefs", [])
                if r.get("referenceType") == "purl"), "")
    path = raw.split("#", 1)[0].split("?", 1)[0]
    # A scoped npm name contains @ before the last slash; that is not a version.
    if path.rfind("@") > path.rfind("/"):
        path = path.rsplit("@", 1)[0]
    qualifiers = parse_qs(urlsplit(raw).query)
    purl = path or None
    ecosystem = None
    kind = path.removeprefix("pkg:").split("/", 1)[0]
    ecosystems = {"golang": "Go", "npm": "npm", "pypi": "PyPI", "maven": "Maven",
                  "gem": "RubyGems", "cargo": "crates.io", "nuget": "NuGet", "hex": "Hex", "pub": "Pub"}
    if kind == "apk":
        release = qualifiers.get("distro", [""])[0]
        match = re.fullmatch(r"alpine-(\d+\.\d+)(?:\.\d+)?", release)
        alpine_version = "v" + match[1] if match else alpine_version
        ecosystem = "Alpine:" + alpine_version if alpine_version else "Alpine"
    elif kind == "deb":
        match = re.fullmatch(r"debian-(\d+)(?:\.\d+)?", qualifiers.get("distro", [""])[0])
        ecosystem = "Debian:" + match[1] if match else "Debian"
    elif kind in ecosystems:
        ecosystem = ecosystems[kind]
    elif kind == "generic" and path.rsplit("/", 1)[-1] in ("kernel", "linux", "linux-kernel"):
        ecosystem = "Linux"
    if kind in ("apk", "deb"):
        origin = qualifiers.get("upstream", [])
        if len(origin) == 1:
            name = origin[0].split("@", 1)[0]
    if not ecosystem:
        source = (package.get("sourceInfo") or "").lower()
        if "apk db" in source:
            ecosystem = "Alpine:" + alpine_version if alpine_version else "Alpine"
        elif "go module" in source:
            ecosystem = "Go"
    if ecosystem == "Go" and path.startswith("pkg:golang/"):
        name = unquote(path.removeprefix("pkg:golang/"))
    elif kind == "npm":
        name = unquote(path.removeprefix("pkg:npm/"))
    elif kind == "maven":
        name = unquote(path.removeprefix("pkg:maven/")).replace("/", ":", 1)
    if name in ("Kernel", "Linux"):
        ecosystem = "Linux"
    if ecosystem == "Linux":
        name = "Kernel"
    return {"name": name, "version": version, "purl": purl, "ecosystem": ecosystem,
            **{k: package.get(k) for k in ("sourceInfo", "packageFileName", "description")}}

def parse_spdx(file_path):
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            spdx_data = json.load(file)

        if "packages" not in spdx_data or not spdx_data["packages"]:
            log.info("No packages found in SPDX file.")
            return None

        # Merged EVE SBOMs retain original unscoped container records as well
        # as copies carrying packageFileName. Do not treat the originals as
        # host packages and apply the host's Alpine release to them.
        raw_packages = spdx_data["packages"]
        def record_key(pkg):
            return pkg.get("SPDXID"), pkg.get("name"), pkg.get("versionInfo")
        scoped = {record_key(pkg) for pkg in raw_packages
                  if pkg.get("packageFileName") and pkg.get("SPDXID")}
        relationships = spdx_data.get("relationships", [])
        roots = {r.get("relatedSpdxElement") for r in relationships
                 if r.get("relationshipType") == "DESCRIBES"
                 and r.get("spdxElementId") == spdx_data.get("SPDXID")}
        # EVE also merges document-root IDs such as "Directory-sbom" from
        # multiple container SBOMs. Such reused roots cannot prove host ownership.
        roots -= {pkg.get("SPDXID") for pkg in raw_packages if pkg.get("packageFileName")}
        root_packages = {r.get("relatedSpdxElement") for r in relationships
                         if r.get("relationshipType") == "CONTAINS"
                         and r.get("spdxElementId") in roots}
        for package in raw_packages:
            if (not package.get("packageFileName") and record_key(package) in scoped
                    and package.get("SPDXID") not in root_packages):
                continue
            package_info = {
                # required fields
                "name": package.get("name", "Unknown"),
                "SPDXID": package.get("SPDXID", "Unknown"),
                "downloadLocation": package.get("downloadLocation", "NOASSERTION"),

                # commonly used fields
                "versionInfo": package.get("versionInfo", None),
                "packageFileName": package.get("packageFileName", None),
                "supplier": package.get("supplier", "NOASSERTION"),
                "originator": package.get("originator", "NOASSERTION"),
                "filesAnalyzed": package.get("filesAnalyzed", True),
                "packageVerificationCode": package.get("packageVerificationCode", None),
                "checksums": package.get("checksums", []),
                "homepage": package.get("homepage", None),
                "sourceInfo": package.get("sourceInfo", None),

                # license information
                "licenseConcluded": package.get("licenseConcluded", "NOASSERTION"),
                "licenseDeclared": package.get("licenseDeclared", "NOASSERTION"),
                "licenseInfoFromFiles": package.get("licenseInfoFromFiles", []),
                "licenseComments": package.get("licenseComments", None),
                "copyrightText": package.get("copyrightText", "NOASSERTION"),

                # descriptive fields
                "summary": package.get("summary", None),
                "description": package.get("description", None),
                "comment": package.get("comment", None),

                # external references (for CPE, PURL, etc.)
                "externalRefs": package.get("externalRefs", []),

                # package purpose and metadata
                "primaryPackagePurpose": package.get("primaryPackagePurpose", None),
                "releaseDate": package.get("releaseDate", None),
                "builtDate": package.get("builtDate", None),
                "validUntilDate": package.get("validUntilDate", None),
            }

            packages.append(package_info)

    except FileNotFoundError:
        log.error(f"Error: SPDX file not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        log.error(f"Error: Invalid JSON in SPDX file: {e}")
        return None
    except Exception as e:
        log.error(f"Error reading SPDX file: {e}")
        return None

    return packages


def load_cvss_bt_cache(csv_path):
    cvss_bt_data = {}
    try:
        with open(csv_path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                cve_id = row.get("CVE") or row.get("cve")
                if cve_id:
                    cvss_bt_data[cve_id.lower()] = row
        log.info(f"Loaded {len(cvss_bt_data)} CVSS BT entries from {csv_path}")
    except FileNotFoundError:
        log.warning(f"Warning: CVSS BT file not found: {csv_path}")
    except Exception as e:
        log.error(f"Error loading CVSS BT data: {e}")

    return cvss_bt_data

_OSV_RETRY_STATUS = {429, 500, 502, 503, 504}


def _osv_post(url, payload, max_retries=5):
    """POST to OSV, retrying on 429/5xx and network errors with exponential
    backoff. Returns the 200 response, or None if it ultimately fails."""
    delay = 1.0
    for attempt in range(max_retries):
        response = None
        try:
            response = requests.post(url, json=payload, timeout=30)
        except requests.exceptions.RequestException as e:
            log.debug(f"OSV request error (attempt {attempt + 1}/{max_retries}): {e}")

        if response is not None:
            if response.status_code == 200:
                return response
            if response.status_code not in _OSV_RETRY_STATUS:
                log.warning(f"OSV HTTP {response.status_code}: "
                            f"{response.text[:200] if response.text else ''}")
                return None
            log.debug(f"OSV HTTP {response.status_code}, retrying "
                      f"(attempt {attempt + 1}/{max_retries})")

        if attempt < max_retries - 1:
            time.sleep(delay + random.uniform(0, 0.3))
            delay *= 2

    log.warning(f"OSV request failed after {max_retries} attempts")
    return None


def _is_go_toolchain(name=None, ecosystem=None, purl=None):
    if purl:
        package = purl.split("?", 1)[0].split("#", 1)[0].split("@", 1)[0]
        return package in ("pkg:golang/stdlib", "pkg:golang/toolchain")
    return ecosystem == "Go" and name in ("stdlib", "toolchain")


def _go_osv_version(version):
    """Convert Go build-info versions to OSV semver, without changing the SBOM.

    Sending e.g. go1.26.10 to OSV can return the entire stdlib advisory list.
    Unknown/development builds must not become unversioned queries either.
    """
    if not isinstance(version, str):
        raise ValueError("missing Go toolchain version")
    if version == "go1":
        return "1.0.0"
    match = re.fullmatch(
        r"(?:go|v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:\.(0|[1-9][0-9]*))?(?:(?:-?)(beta|rc|pre)\.?([1-9][0-9]*))?",
        version,
    )
    if not match:
        raise ValueError(f"unsupported Go toolchain version: {version!r}")
    major, minor, patch, prerelease, number = match.groups()
    result = f"{major}.{minor}.{patch or '0'}"
    if prerelease:
        result += f"-{prerelease}.{number}"
    return result


def get_osv_vulnerabilities(name=None, version=None, ecosystem=None, purl=None, max_pages=100):
    """Return a complete query response, or None. Never return partial pages."""
    if _is_go_toolchain(name, ecosystem, purl):
        try:
            version = _go_osv_version(version)
        except ValueError as exc:
            log.error("Go advisory coverage unresolved: %s", exc)
            return None
    if not version:
        log.warning("Cannot query unversioned package %s", name or purl)
        return None
    if purl:
        package = {"purl": purl}
    elif name and ecosystem:
        package = {"name": name, "ecosystem": ecosystem}
    else:
        return None
    payload = {"package": package, "version": version}
    all_vulns, seen = [], set()
    try:
        for _ in range(max_pages):
            response = _osv_post("https://api.osv.dev/v1/query", payload)
            if response is None:
                return None
            data = response.json()
            if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
                raise ValueError("invalid OSV response")
            page = data.get("vulns", [])
            if not all(isinstance(v, dict) and isinstance(v.get("id"), str) for v in page):
                raise ValueError("invalid advisory record")
            all_vulns.extend(page)
            token = data.get("next_page_token")
            if not token:
                return {"vulns": all_vulns} if all_vulns else {}
            if not isinstance(token, str) or token in seen:
                raise ValueError("OSV pagination did not advance")
            seen.add(token)
            payload = {**payload, "page_token": token}
        raise ValueError("OSV pagination limit exceeded")
    except (requests.RequestException, ValueError, TypeError) as exc:
        log.error("OSV query incomplete: %s", exc)
        return None

def load_linux_kernel_db(cache_dir):
    """Refresh atomically; a partial or stale archive cannot pass the gate."""
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, "Linux_all.zip")
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < OSV_CACHE_TTL_SECONDS:
        if zipfile.is_zipfile(path):
            return path
    fd, tmp = tempfile.mkstemp(dir=cache_dir, suffix=".zip.tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            with requests.get("https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip",
                              timeout=(10, 120), stream=True) as response:
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=65536):
                    out.write(chunk)
        with zipfile.ZipFile(tmp) as archive:
            if not archive.namelist() or archive.testzip() is not None:
                raise ScanError("Invalid Linux advisory archive")
        os.replace(tmp, path)
        return path
    except (requests.RequestException, OSError, zipfile.BadZipFile) as exc:
        raise ScanError("Could not refresh Linux advisory archive") from exc
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def version_in_range(target, events):
    """Evaluate the OSV event timeline, not assumed introduced/fixed pairs.

    OSV permits repeated fixed events and does not require sorted input. Limits
    are an independent scope check. See https://ossf.github.io/osv-schema/#evaluation.
    """
    timeline, limits = [], []
    introduced = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ScanError("Malformed Linux affected event")
        kind, value = next(iter(event.items()))
        if kind == "limit":
            limits.append(None if value == "*" else packaging_version.Version(value))
        elif kind in ("introduced", "fixed", "last_affected"):
            timeline.append((packaging_version.Version(value), kind))
            introduced = introduced or kind == "introduced"
        else:
            raise ScanError("Unknown Linux affected event")
    if not introduced:
        raise ScanError("Linux range has no introduced event")
    if limits and not any(limit is None or target < limit for limit in limits):
        return False
    vulnerable = False
    for version, kind in sorted(timeline, key=lambda item: item[0]):
        if kind == "introduced" and target >= version:
            vulnerable = True
        elif kind == "fixed" and target >= version:
            vulnerable = False
        elif kind == "last_affected" and target > version:
            vulnerable = False
    return vulnerable


def check_linux_kernel_vulns(version_str, db_zip_path):
    """Match each numeric version interval, including disjoint affected ranges."""
    target = packaging_version.Version(version_str)
    found = []
    if not db_zip_path:
        raise ScanError("Linux advisory archive unavailable")
    try:
        with zipfile.ZipFile(db_zip_path) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                with archive.open(name) as entry:
                    vuln = json.load(entry)
                if vuln.get("withdrawn"):
                    continue
                matched = False
                for affected in vuln.get("affected", []):
                    if affected.get("package", {}).get("ecosystem") != "Linux":
                        continue
                    if version_str in affected.get("versions", []):
                        matched = True
                    for span in affected.get("ranges", []):
                        if span.get("type") not in ("SEMVER", "ECOSYSTEM"):
                            continue
                        if version_in_range(target, span.get("events", [])):
                            matched = True
                if matched:
                    found.append(vuln)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise ScanError("Could not read Linux advisory archive") from exc
    return found

def get_cache_dir(base_dir):
    # Stable dir; per-entry 8h expiry (see OSV_CACHE_TTL_SECONDS) bounds staleness.
    cache_dir = os.path.join(str(base_dir), "queries")
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def _maybe_inject_kernel(spdx_packages, alpine_version, kernel_version):
    """Append a generic Linux kernel package if `kernel_version` is given and the
    SBOM has no kernel package. Mutates `spdx_packages` in place."""
    if not kernel_version:
        return
    for pkg in spdx_packages:
        info = extract_package_info(pkg, alpine_version)
        if info["ecosystem"] == "Linux" or info["name"] in ("Kernel", "Linux"):
            return
    clean_ver = kernel_version.lstrip("v")
    log.info("Kernel not in SBOM; adding Linux kernel version %s", clean_ver)
    spdx_packages.append({
        "name": "Kernel",
        "versionInfo": clean_ver,
        "externalRefs": [{
            "referenceType": "purl",
            "referenceLocator": f"pkg:generic/kernel@{clean_ver}",
        }],
    })


def _query_osv(pkg_info, cache):
    """Return OSV vulns for one non-kernel package (dict, possibly empty) or None
    on API error. Reads and populates the 8h query cache."""
    if not pkg_info["ecosystem"]:
        log.warning("Primary coverage unresolved: unsupported ecosystem for %s", pkg_info["name"])
        return {}  # Exact source commits can still be covered by the additive pass.
    if not pkg_info["version"]:
        log.warning("Coverage unresolved: no version for %s", pkg_info["name"])
        return {}
    if pkg_info["ecosystem"] in ("Alpine", "Debian"):
        log.warning("Coverage unresolved: no distro release for %s", pkg_info["name"])
        return {}
    go_toolchain = _is_go_toolchain(pkg_info["name"], pkg_info["ecosystem"], pkg_info["purl"])
    if go_toolchain:
        try:
            pkg_info = {**pkg_info, "version": _go_osv_version(pkg_info["version"])}
        except ValueError as exc:
            log.error("Go advisory coverage unresolved: %s", exc)
            return None
    cache_key = ("query-v2", pkg_info["name"], pkg_info["version"],
                 pkg_info["ecosystem"], pkg_info["purl"])
    if go_toolchain:
        # Never reuse pre-fix responses, including cached empty/purl results.
        cache_key = ("go-toolchain-semver-v1", *cache_key)
    cached = cache.get(cache_key, default=_CACHE_MISS)
    if cached is not _CACHE_MISS:
        log.debug("    Retrieved vulnerabilities from cache.")
        return cached

    vulns_data = None
    # Query by name + ecosystem first.
    if pkg_info["name"] and pkg_info["ecosystem"]:
        vulns_data = get_osv_vulnerabilities(
            name=pkg_info["name"], version=pkg_info["version"],
            ecosystem=pkg_info["ecosystem"])
    elif not pkg_info["purl"]:
        log.debug("    Skipping %s - no ecosystem or purl to query",
                  pkg_info["name"] or "<unnamed>")
        vulns_data = {}

    # Fall back to a purl query, but don't let its errors mask a valid (empty)
    # name-query result.
    if not vulns_data and pkg_info["purl"] and not (pkg_info["ecosystem"] or "").startswith(("Alpine", "Debian")):
        purl_result = get_osv_vulnerabilities(
            purl=pkg_info["purl"], version=pkg_info["version"])
        if purl_result is not None:
            vulns_data = purl_result

    # Cache only valid results, never transient network errors.
    if vulns_data is not None:
        cache.set(cache_key, vulns_data, expire=OSV_CACHE_TTL_SECONDS)
    return vulns_data


def _write_results(results, output_file):
    """Write the enriched SBOM (scan results) as JSON to `output_file`.

    Writes to a temp file in the same directory then atomically renames it, so
    a killed process can never leave a half-written JSON that a later run would
    reuse (the skip-if-exists logic treats any existing file as complete)."""
    try:
        d = os.path.dirname(os.path.abspath(output_file))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out_file:
                json.dump(results, out_file, indent=2)
                out_file.flush()
                os.fsync(out_file.fileno())
            os.replace(tmp, output_file)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        log.info("Scan results saved to %s", output_file)
    except Exception as exc:
        raise ScanError(f"Error saving scan results: {exc}") from exc


def scan_sbom(sbom_file, cvss_bt_path, alpine_db_path, output_file,
              osv_cache_dir, kernel_version=None):
    # A failed new scan must not leave an old successful output to be uploaded.
    if os.path.exists(output_file):
        os.unlink(output_file)
    packages = parse_spdx(sbom_file)
    if not packages:
        raise ScanError(f"Missing, malformed or empty SPDX packages: {sbom_file}")
    from scan.fallback import releases_by_container, run_additive, package_key
    releases = releases_by_container(packages)
    cvss_data = load_cvss_bt_cache(cvss_bt_path) or {}
    _maybe_inject_kernel(packages, None, kernel_version)
    results, failures = [], []
    linux_db = None
    with Cache(get_cache_dir(osv_cache_dir)) as cache:
        for pkg in packages:
            # Mixed-container EVE SBOMs can contain different Alpine releases.
            info = extract_package_info(pkg, releases.get(pkg.get("packageFileName") or ""))
            log.info("Checking %s %s (%s)", info["name"], info["version"], info["ecosystem"])
            if info["ecosystem"] == "Linux" or info["name"] == "Kernel":
                match = re.match(r"v?(\d+\.\d+(?:\.\d+)?)(?:-|$)", info["version"] or "")
                if not match:
                    failures.append(f"Unknown kernel version: {info['version']}")
                    continue
                if linux_db is None:
                    linux_db = load_linux_kernel_db(osv_cache_dir)
                data = {"vulns": check_linux_kernel_vulns(match[1], linux_db)}
            else:
                data = _query_osv(info, cache)
            if data is None:
                failures.append(f"Advisory lookup failed: {info['name']} {info['version']}")
                continue
            accepted = []
            for original in data.get("vulns", []):
                if original.get("withdrawn"):
                    continue
                vuln = copy.deepcopy(original)
                ids = {v for v in [vuln.get("id"), *vuln.get("aliases", []), *vuln.get("upstream", [])] if v}
                # The legacy APKBUILD database flattens fixed versions away.
                # It cannot prove an installed revision is fixed. Scoped OSV
                # queries and the evidence-gated fallback retain version checks.
                vuln["exploitability"] = [cvss_data[v.lower()] for v in sorted(ids) if v.lower() in cvss_data]
                accepted.append(vuln)
            if accepted:
                results.append({"package": pkg, "vulnerabilities": accepted})
        try:
            additions = run_additive(packages, results, cache, cvss_data, output_file)
            by_package = {package_key(row["package"]): row for row in results}
            for row in additions:
                existing = by_package.get(package_key(row["package"]))
                if existing is not None:
                    existing["vulnerabilities"].extend(row["vulnerabilities"])
                else:
                    results.append(row)
                    by_package[package_key(row["package"])] = row
        except Exception:
            log.exception("Supplemental fallback unavailable; primary findings retained")
    if failures:
        _write_results(results, str(output_file) + ".partial.json")
        raise ScanError("Incomplete primary scan: " + "; ".join(failures))
    _write_results(results, output_file)


def main():
    parser = argparse.ArgumentParser(description="Scan an EVE SPDX SBOM")
    parser.add_argument("eve_tag", help="Output label, not a source revision")
    parser.add_argument("sbom_file")
    parser.add_argument("cvss_bt_path")
    parser.add_argument("alpine_db_path", help="Legacy argument retained for existing callers")
    parser.add_argument("output_dir")
    parser.add_argument("--kernel-version", help="Kernel from the exact scanned source revision, if absent in SBOM")
    parser.add_argument("--cache-dir", default="out/cache/osv")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    output = os.path.join(args.output_dir, "scan_results_" + args.eve_tag.replace("/", "_") + ".json")
    try:
        scan_sbom(args.sbom_file, args.cvss_bt_path, args.alpine_db_path, output,
                  args.cache_dir, kernel_version=args.kernel_version)
    except (ScanError, OSError, ValueError) as exc:
        log.error("%s", exc)
        return 2
    return 0


if __name__ == "__main__":
    # Retain python ci/scan/scanner.py ... as well as python -m scan.scanner.
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    raise SystemExit(main())
