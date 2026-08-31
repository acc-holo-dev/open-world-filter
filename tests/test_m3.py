import json
import tempfile
import unittest
from pathlib import Path

from pipeline import geo_dat, subscriptions
from pipeline.community_check import check_community, validate_additions, validate_exclusions
from pipeline.emit import build_provenance, write_provenance_gz
from pipeline.provenance import Entry, Evidence


def make_entry(value, kind="domain", tier="auto", flags=None, evs=None):
    return Entry(value=value, kind=kind, tier=tier, flags=flags or [],
                 evidence=evs or [Evidence(source="test", fetched_at="2026-01-01T00:00:00Z",
                                           reason="unit", url="https://example.test")])


class CommunityCheckTests(unittest.TestCase):
    def test_valid_files_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            comm = root / "community"
            comm.mkdir()
            (comm / "additions.txt").write_text("example.org\n198.51.100.0/24\n# comment\n", encoding="utf-8")
            (comm / "exclusions.txt").write_text("!suffix: example.test\n", encoding="utf-8")
            report = check_community(root)
            self.assertTrue(report["ok"])
            self.assertEqual(report["errors"], [])

    def test_duplicate_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "additions.txt"
            p.write_text("example.org\nexample.org\n", encoding="utf-8")
            errors, stats = validate_additions(p)
            self.assertIn("дубликат", errors[0])
            self.assertEqual(stats["duplicates"], 1)

    def test_junk_line_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "additions.txt"
            p.write_text("not a domain @@@\n", encoding="utf-8")
            errors, stats = validate_additions(p)
            self.assertTrue(errors)
            self.assertEqual(stats["junk"], 1)

    def test_adguard_exclusion_rejected_in_additions(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "additions.txt"
            p.write_text("!suffix: example.test\n", encoding="utf-8")
            errors, stats = validate_additions(p)
            self.assertTrue(any("exclusions.txt" in e for e in errors))
            self.assertEqual(stats["junk"], 1)

    def test_adguard_network_rule_is_accepted(self):
        # «||domain^» — блокирующее правило AdGuard: срезается до домена, это валидно
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "additions.txt"
            p.write_text("||example.org^\n", encoding="utf-8")
            errors, stats = validate_additions(p)
            self.assertEqual(errors, [])
            self.assertEqual(stats["accepted"], 1)

    def test_exclusion_duplicate_and_unsupported(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "exclusions.txt"
            p.write_text("!suffix: towiru\n!suffix: towiru\n!keyword: spam\n", encoding="utf-8")
            errors, stats = validate_exclusions(p)
            self.assertTrue(any("дубликат" in e for e in errors))
            self.assertTrue(any("keyword" in e for e in errors))
            self.assertEqual(stats["unsupported"], 1)


class GeoDatTests(unittest.TestCase):
    def test_xray_config(self):
        cfg = geo_dat.render_xray_geoip_config(Path("out/owf-ips.lst"))
        self.assertEqual(cfg["output"][0]["type"], "v2rayGeoIPDat")
        self.assertEqual(cfg["output"][0]["args"]["wantedList"], ["owf", "private"])
        self.assertEqual(cfg["input"][0]["args"]["name"], "owf")

    def test_prepare_all_writes_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "out"
            out.mkdir()
            (out / "owf-ips.lst").write_text("1.2.3.0/24\n", encoding="utf-8")
            (out / "owf-domains.lst").write_text("example.org\n", encoding="utf-8")
            geo_dat.prepare_all(root, out)
            self.assertTrue((out / "convert-input" / "include-ip-owf.lst").exists())
            self.assertTrue((out / "convert-input" / "include-domain-owf.lst").exists())
            cfg = json.loads((out / "convert-input" / "owf-geoip.json").read_text(encoding="utf-8"))
            self.assertTrue(cfg["input"][0]["args"]["uri"].endswith("owf-ips.lst"))


class ProvenanceTests(unittest.TestCase):
    def test_build_and_gzip(self):
        entries = [make_entry("example.org"), make_entry("203.0.113.5", kind="ip")]
        cache = {"example.org": {"status": "alive", "parked": False, "checked_at": "2026-01-01"}}
        data = build_provenance(entries, cache)
        self.assertEqual(data["example.org"]["probe"]["status"], "alive")
        self.assertEqual(data["example.org"]["evidence"][0]["source"], "test")
        self.assertEqual(data["203.0.113.5"]["kind"], "ip")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "provenance.json.gz"
            size = write_provenance_gz(data, p)
            import gzip
            raw = gzip.decompress(p.read_bytes())
            parsed = json.loads(raw)
            self.assertIn("example.org", parsed)
            self.assertGreater(size, 0)

    def test_manifest_has_provenance(self):
        manifest = subscriptions.render_manifest("acc-holo-dev", "open-world-filter")
        self.assertTrue(manifest["clients"]["provenance-gz"].endswith("provenance.json.gz"))


if __name__ == "__main__":
    unittest.main()
