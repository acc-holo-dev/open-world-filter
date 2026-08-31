import tempfile
import unittest
from pathlib import Path

from pipeline.emit import apply_policy, render_forge_toml
from pipeline.probe import TTL_MAP, classify_dns, collect_ips_from_cache, is_expired, is_parked
from pipeline.provenance import Entry
from pipeline.resolve import collect_ips_from_entries
from pipeline.summarize import normalize_to_networks, summarize


class ClassifyTests(unittest.TestCase):
    def test_nxdomain_is_dead(self):
        self.assertEqual(classify_dns("NXDOMAIN", 0), "dead")

    def test_noanswer_with_records_is_alive(self):
        self.assertEqual(classify_dns("NOERROR", 2), "alive")

    def test_noanswer_without_records_is_empty(self):
        self.assertEqual(classify_dns("NOANSWER", 0), "empty")
        self.assertEqual(classify_dns("NOERROR", 0), "empty")

    def test_servfail_and_timeout_are_error_not_dead(self):
        # прозрачность: неизвестный результат — НЕ мёртвый домен
        self.assertEqual(classify_dns("SERVFAIL", 0), "error")
        self.assertEqual(classify_dns("TIMEOUT", 0), "error")


class ParkedTests(unittest.TestCase):
    def test_parked_ns(self):
        self.assertTrue(is_parked(["NS1.SEDOPARKING.COM."]))
        self.assertTrue(is_parked(["ns1.parklogic.com"]))

    def test_normal_ns(self):
        self.assertFalse(is_parked(["ns1.cloudflare.com", "ns2.cloudflare.com"]))
        self.assertFalse(is_parked([]))


class TtlTests(unittest.TestCase):
    def test_alive_ttl_long_dead_ttl_long_error_ttl_short(self):
        now = 1000000.0
        fresh = {"status": "alive", "checked_at": now - 10}
        self.assertFalse(is_expired(fresh, now))
        old_alive = {"status": "alive", "checked_at": now - TTL_MAP["alive"] - 1}
        self.assertTrue(is_expired(old_alive, now))
        old_dead = {"status": "dead", "checked_at": now - TTL_MAP["dead"] - 1}
        self.assertTrue(is_expired(old_dead, now))
        # error перепроверяется быстро
        recent_error = {"status": "error", "checked_at": now - TTL_MAP["error"] - 1}
        self.assertTrue(is_expired(recent_error, now))

    def test_missing_record_is_expired_via_get(self):
        # домена нет в кэше -> его просто нет в dict; проверяем запись без checked_at
        self.assertTrue(is_expired({"status": "alive"}, 0.0))


class CacheIpsTests(unittest.TestCase):
    def test_only_alive_ips_collected(self):
        cache = {
            "a.com": {"status": "alive", "ips": ["1.2.3.4", "5.6.7.8"]},
            "b.com": {"status": "alive", "ips": ["1.2.3.4"]},
            "c.com": {"status": "dead", "ips": ["9.9.9.9"]},
            "d.com": {"status": "empty", "ips": []},
        }
        self.assertEqual(collect_ips_from_cache(cache), ["1.2.3.4", "5.6.7.8"])


class EntryIpsTests(unittest.TestCase):
    def test_collect_from_entries(self):
        entries = [
            Entry(value="example.com", kind="domain"),
            Entry(value="1.2.3.4", kind="ip"),
            Entry(value="10.0.0.0/8", kind="cidr"),
            Entry(value="1.2.3.4", kind="ip"),  # дубль
        ]
        self.assertEqual(collect_ips_from_entries(entries), ["1.2.3.4", "10.0.0.0/8"])


class SummarizeTests(unittest.TestCase):
    def test_normalize_bare_ip_to_network(self):
        nets = normalize_to_networks(["1.2.3.4", "10.0.0.0/8", "junk", ""])
        values = sorted(str(n) for n in nets)
        self.assertEqual(values, ["1.2.3.4/32", "10.0.0.0/8"])

    def test_collapse_adjacent(self):
        cidrs, report = summarize(["1.2.3.4", "1.2.3.5", "1.2.3.6"])
        self.assertEqual(cidrs, ["1.2.3.4/31", "1.2.3.6/32"])
        self.assertEqual(report["output_cidrs"], 2)

    def test_asn_groups_do_not_merge(self):
        # соседние IP из разных автономок НЕ сливаются в одну подсеть
        asn_map = {
            "1.2.3.4": [64500, "Test A"],
            "1.2.3.5": [64501, "Test B"],
        }
        cidrs, report = summarize(["1.2.3.4", "1.2.3.5"], asn_map)
        self.assertEqual(cidrs, ["1.2.3.4/32", "1.2.3.5/32"])
        self.assertEqual(report["groups_count"], 2)
        self.assertEqual(report["groups"]["64500"]["name"], "Test A")

    def test_same_asn_merges(self):
        asn_map = {
            "1.2.3.4": [64500, "Test A"],
            "1.2.3.5": [64500, "Test A"],
        }
        cidrs, _ = summarize(["1.2.3.4", "1.2.3.5"], asn_map)
        self.assertEqual(cidrs, ["1.2.3.4/31"])


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.entries = [
            Entry(value="dead.example", kind="domain"),
            Entry(value="alive.example", kind="domain"),
            Entry(value="unknown.example", kind="domain"),
            Entry(value="empty.example", kind="domain"),
            Entry(value="parked.example", kind="domain"),
            Entry(value="1.2.3.4", kind="ip"),
        ]
        self.cache = {
            "dead.example": {"status": "dead"},
            "alive.example": {"status": "alive"},
            "empty.example": {"status": "empty"},
            "parked.example": {"status": "alive", "parked": True},
        }

    def test_dead_dropped_by_default(self):
        kept, stats = apply_policy(self.entries, self.cache)
        values = [e.value for e in kept]
        self.assertNotIn("dead.example", values)
        self.assertIn("alive.example", values)
        self.assertIn("unknown.example", values)   # нет в кэше — остаётся
        self.assertIn("empty.example", values)     # пустой — не мёртвый
        self.assertIn("parked.example", values)    # запаркованный всё равно заблокирован
        self.assertNotIn("1.2.3.4", values)        # не домен
        self.assertEqual(stats["dropped_dead"], 1)
        self.assertEqual(stats["kept_parked"], 1)

    def test_keep_dead_flag(self):
        kept, stats = apply_policy(self.entries, self.cache, keep_dead=True)
        self.assertIn("dead.example", [e.value for e in kept])
        self.assertEqual(stats["dropped_dead"], 0)


class ForgeTomlTests(unittest.TestCase):
    def test_render_contains_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            domains = Path(tmp) / "owf-domains.lst"
            ips = Path(tmp) / "owf-ips.lst"
            domains.write_text("a.example\n", encoding="utf-8")
            ips.write_text("1.2.3.4/32\n", encoding="utf-8")
            text = render_forge_toml(domains.resolve(), ips.resolve(), "acc-holo-dev", "open-world-filter")
        self.assertIn('owner = "acc-holo-dev"', text)
        self.assertIn('name = "open-world-filter"', text)
        self.assertIn("[targets.proxy]", text)
        self.assertIn("kind = \"domains\"", text)
        self.assertIn("kind = \"ips\"", text)
        self.assertIn("file://", text)
        self.assertIn("owf-domains.lst", text)


if __name__ == "__main__":
    unittest.main()
