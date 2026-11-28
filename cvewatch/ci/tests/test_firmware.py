# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diskcache import Cache
from scan import scanner

VERSION = "20260916"
DEBIAN, UBUNTU = (ecosystem for _, ecosystem in scanner.FIRMWARE_ADVISORY_STREAMS)
FIRMWARE = {
    "name": "linux-firmware", "versionInfo": VERSION, "SPDXID": "SPDXRef-linux-firmware",
    "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/linux-firmware@" + VERSION}],
}


def advisory(identifier, cve):
    return {"id": identifier, "upstream": [cve]}


def streams(by_ecosystem):
    """A get_osv_vulnerabilities stand-in: the advisories (or None, a failed
    lookup) listed for each ecosystem, nothing for the others."""
    def query(name=None, version=None, ecosystem=None, purl=None, max_pages=100):
        found = by_ecosystem.get(ecosystem, [])
        return None if found is None else ({"vulns": found} if found else {})
    return query


class FirmwareTests(unittest.TestCase):
    def test_package_is_not_labelled_alpine(self):
        info = scanner.extract_package_info(FIRMWARE, "v3.22")
        self.assertEqual(info["ecosystem"], scanner.FIRMWARE_ECOSYSTEM)
        self.assertEqual(info["purl"], "pkg:generic/linux-firmware")

    def test_every_stream_is_queried_by_name_and_ecosystem_only(self):
        info = scanner.extract_package_info(FIRMWARE, "v3.22")
        with tempfile.TemporaryDirectory() as directory, Cache(directory) as cache, \
             patch.object(scanner, "get_osv_vulnerabilities", return_value={}) as query:
            self.assertEqual(scanner._query_firmware(info, cache), {})
        self.assertEqual(
            [call.kwargs for call in query.call_args_list],
            [{"name": name, "version": VERSION, "ecosystem": ecosystem}
             for name, ecosystem in scanner.FIRMWARE_ADVISORY_STREAMS])

    def test_cve_listed_by_both_distributions_is_returned_once(self):
        info = scanner.extract_package_info(FIRMWARE, "v3.22")
        query = streams({
            DEBIAN: [advisory("DEBIAN-CVE-2022-27635", "CVE-2022-27635")],
            UBUNTU: [advisory("UBUNTU-CVE-2022-27635", "CVE-2022-27635"),
                     advisory("UBUNTU-CVE-2021-0066", "CVE-2021-0066")]})
        with tempfile.TemporaryDirectory() as directory, Cache(directory) as cache, \
             patch.object(scanner, "get_osv_vulnerabilities", side_effect=query):
            data = scanner._query_firmware(info, cache)
        self.assertEqual([v["id"] for v in data["vulns"]],
                         ["DEBIAN-CVE-2022-27635", "UBUNTU-CVE-2021-0066"])

    def test_failed_stream_fails_the_lookup(self):
        info = scanner.extract_package_info(FIRMWARE, "v3.22")
        query = streams({DEBIAN: [advisory("DEBIAN-CVE-2022-27635", "CVE-2022-27635")], UBUNTU: None})
        with tempfile.TemporaryDirectory() as directory, Cache(directory) as cache, \
             patch.object(scanner, "get_osv_vulnerabilities", side_effect=query):
            self.assertIsNone(scanner._query_firmware(info, cache))

    def scan(self, query, directory):
        output = Path(directory) / "scan.json"
        with patch.object(scanner, "parse_spdx", return_value=[FIRMWARE]), \
             patch.object(scanner, "load_cvss_bt_cache", return_value={"cve-2022-27635": {"CVSS": "7.5"}}), \
             patch.object(scanner, "get_osv_vulnerabilities", side_effect=query), \
             patch("scan.fallback.run_additive", return_value=[]):
            scanner.scan_sbom("sbom", "cvss", "none", str(output), directory)
        return json.loads(output.read_text())

    def test_scan_reports_firmware_advisories(self):
        query = streams({UBUNTU: [advisory("UBUNTU-CVE-2022-27635", "CVE-2022-27635")]})
        with tempfile.TemporaryDirectory() as directory:
            rows = self.scan(query, directory)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["package"], FIRMWARE)
        self.assertEqual([v["id"] for v in rows[0]["vulnerabilities"]], ["UBUNTU-CVE-2022-27635"])
        self.assertEqual(rows[0]["vulnerabilities"][0]["exploitability"], [{"CVSS": "7.5"}])

    def test_scan_fails_when_a_stream_lookup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(scanner.ScanError):
                self.scan(streams({DEBIAN: None}), directory)


if __name__ == "__main__":
    unittest.main()
