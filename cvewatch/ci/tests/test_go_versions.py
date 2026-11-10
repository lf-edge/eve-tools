import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diskcache import Cache
from scan import scanner


def package(version):
    return {
        "name": "stdlib", "versionInfo": version, "SPDXID": "SPDX-stdlib",
        "sourceInfo": "acquired package info from go module information: /bin/rc.init",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/stdlib@" + version.removeprefix("go")}],
    }


class GoVersionTests(unittest.TestCase):
    def test_query_payload_uses_semver_for_name_and_purl(self):
        cases = {
            "go1.24.9": "1.24.9", "go1.26.10": "1.26.10",
            "1.26.10": "1.26.10", "v1.26.10": "1.26.10",
            "go1.20": "1.20.0", "go1": "1.0.0",
            "go1.27rc1": "1.27.0-rc.1", "go1.27beta2": "1.27.0-beta.2",
            "go1.27-pre1": "1.27.0-pre.1", "1.27.0-rc.1": "1.27.0-rc.1",
        }
        for original, expected in cases.items():
            for name in ("stdlib", "toolchain"):
                for identity in ({"name": name, "ecosystem": "Go"}, {"purl": "pkg:golang/" + name}):
                    with self.subTest(version=original, identity=identity):
                        with patch.object(scanner, "_osv_post", return_value=Mock(json=lambda: {})) as post:
                            self.assertEqual(scanner.get_osv_vulnerabilities(version=original, **identity), {})
                            self.assertEqual(post.call_args.args[1]["version"], expected)

    def test_unknown_toolchains_never_query_all_versions(self):
        for version in (None, "", "devel go1.27-abcdef", "go1.24.9-custom", "unknown", "go1.024.9"):
            with self.subTest(version=version), patch.object(scanner, "_osv_post") as post:
                self.assertIsNone(scanner.get_osv_vulnerabilities(name="stdlib", ecosystem="Go", version=version))
                post.assert_not_called()

    def test_other_package_versions_are_unchanged(self):
        for name, ecosystem, version in (("golang.org/x/net", "Go", "v0.55.0"),
                                         ("go", "Alpine:v3.22", "1.24.9-r0"),
                                         ("stdlib", "PyPI", "go1.24.9")):
            with self.subTest(name=name), patch.object(scanner, "_osv_post", return_value=Mock(json=lambda: {})) as post:
                scanner.get_osv_vulnerabilities(name=name, ecosystem=ecosystem, version=version)
                self.assertEqual(post.call_args.args[1]["version"], version)

    def test_old_cache_is_ignored_and_clean_empty_result_is_cached(self):
        info = scanner.extract_package_info(package("go1.26.10"))
        original = copy.deepcopy(info)
        with tempfile.TemporaryDirectory() as directory, Cache(directory) as cache:
            for version in ("go1.26.10", "1.26.10"):
                cache.set((info["name"], version, info["ecosystem"], info["purl"]),
                          {"vulns": [{"id": "OLD-FALSE-POSITIVE"}]})
            with patch.object(scanner, "_osv_post", return_value=Mock(json=lambda: {})) as post:
                self.assertEqual(scanner._query_osv(info, cache), {})
                self.assertEqual(post.call_count, 2)  # name and purl both use the normalized version
                self.assertTrue(all(c.args[1]["version"] == "1.26.10" for c in post.call_args_list))
                post.reset_mock()
                self.assertEqual(scanner._query_osv(info, cache), {})
                post.assert_not_called()
            self.assertEqual(info, original)

    def test_development_build_does_not_read_or_populate_cache(self):
        info = scanner.extract_package_info(package("devel go1.27-abcdef"))
        cache = Mock()
        with patch.object(scanner, "_osv_post") as post:
            self.assertIsNone(scanner._query_osv(info, cache))
            post.assert_not_called()
            cache.get.assert_not_called()
            cache.set.assert_not_called()

    def test_scan_keeps_real_old_binary_version_but_excludes_fixed_binary(self):
        packages = [package("go1.24.9"), package("go1.26.10")]
        original = copy.deepcopy(packages)
        advisory = {"id": "GO-regression", "aliases": [], "affected": [{
            "package": {"name": "stdlib", "ecosystem": "Go"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.24.13"}]}],
        }]}

        def response(url, payload):
            version = payload["version"]
            self.assertIn(version, ("1.24.9", "1.26.10"))
            return Mock(json=lambda: {"vulns": [copy.deepcopy(advisory)]} if version == "1.24.9" else {})

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.json"
            with patch.object(scanner, "parse_spdx", return_value=packages), \
                 patch.object(scanner, "load_cvss_bt_cache", return_value={}), \
                 patch.object(scanner, "_osv_post", side_effect=response), \
                 patch("scan.fallback.run_additive", return_value=[]):
                scanner.scan_sbom("sbom", "cvss", "none", str(output), directory)
            rows = json.loads(output.read_text())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["package"], original[0])
            self.assertEqual(rows[0]["vulnerabilities"][0]["id"], "GO-regression")
            self.assertEqual(packages, original)


if __name__ == "__main__":
    unittest.main()
