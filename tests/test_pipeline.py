import tempfile
import unittest
from pathlib import Path

from pipeline.classify import apply_exclusions, flag_heuristics, parse_exclusion_rule
from pipeline.collect import collect_source, detect_kind, sanitize_line
from pipeline.config import Source, load_sources
from pipeline.provenance import Entry, load_entries, save_entries


class SanitizeTests(unittest.TestCase):
    def test_comments_and_blanks(self):
        self.assertIsNone(sanitize_line(""))
        self.assertIsNone(sanitize_line("   "))
        self.assertIsNone(sanitize_line("# comment"))
        self.assertIsNone(sanitize_line("!ublock-comment"))

    def test_adguard(self):
        self.assertEqual(sanitize_line("||example.com^"), "example.com")
        self.assertEqual(sanitize_line("||Example.COM^ # trail"), "example.com")

    def test_trailing_comment_and_case(self):
        self.assertEqual(sanitize_line("Example.Com # reason"), "example.com")

    def test_skips_exceptions(self):
        self.assertIsNone(sanitize_line("@@||allowed.com^"))


class DetectKindTests(unittest.TestCase):
    def test_types(self):
        self.assertEqual(detect_kind("example.com"), "domain")
        self.assertEqual(detect_kind("sub.example.co.uk"), "domain")
        self.assertEqual(detect_kind("1.2.3.4"), "ip")
        self.assertEqual(detect_kind("10.0.0.0/8"), "cidr")
        self.assertIsNone(detect_kind("not a domain!!"))
        self.assertIsNone(detect_kind("-bad.example"))


class ExclusionTests(unittest.TestCase):
    @staticmethod
    def _ex(value):
        return Entry(value=value, kind="exclusion", tier="community")

    def test_suffix_removes_subdomains(self):
        kept, removed = apply_exclusions(
            [Entry(value="api.example.com"), Entry(value="example.com"), Entry(value="other.org")],
            [self._ex("suffix:example.com")],
        )
        self.assertEqual([e.value for e in removed], ["api.example.com", "example.com"])
        self.assertEqual([e.value for e in kept], ["other.org"])

    def test_bare_domain_exact(self):
        kept, removed = apply_exclusions(
            [Entry(value="auth.openai.com"), Entry(value="openai.com")],
            [self._ex("auth.openai.com")],
        )
        self.assertEqual([e.value for e in removed], ["auth.openai.com"])
        self.assertEqual([e.value for e in kept], ["openai.com"])

    def test_parse_rules(self):
        self.assertEqual(parse_exclusion_rule("suffix:x.com"), ("suffix", "x.com"))
        self.assertEqual(parse_exclusion_rule("domain:x.com"), ("domain", "x.com"))
        self.assertEqual(parse_exclusion_rule("x.com"), ("domain", "x.com"))
        self.assertIsNone(parse_exclusion_rule("keyword:ads"))


class CollectLocalTests(unittest.TestCase):
    def test_local_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "community").mkdir()
            text = "\n".join([
                "# comment",
                "example.org # reason",
                "1.2.3.0/24",
                "!!bad",
                "junk line here",
            ])
            (root / "community" / "additions.txt").write_text(text + "\n", encoding="utf-8")
            src = Source(name="community", kind="domains", tier="community", file="community/additions.txt")
            entries, err = collect_source(src, root)
            self.assertIsNone(err)
            by_value = {e.value: e for e in entries}
            self.assertIn("example.org", by_value)
            self.assertIn("1.2.3.0/24", by_value)
            self.assertEqual(by_value["example.org"].tier, "community")
            self.assertEqual(by_value["example.org"].evidence[0].source, "community")

    def test_local_exclusions_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "community").mkdir()
            text = "\n".join(["# comment", "!suffix:example.com", "!domain:x.org"])
            (root / "community" / "exclusions.txt").write_text(text + "\n", encoding="utf-8")
            src = Source(name="excl", kind="exclusions", tier="community", file="community/exclusions.txt")
            entries, err = collect_source(src, root)
            self.assertIsNone(err)
            self.assertEqual([e.value for e in entries], ["suffix:example.com", "domain:x.org"])

    def test_offline_skips_remote(self):
        src = Source(name="remote", kind="domains", url="https://example.invalid/list.txt")
        entries, err = collect_source(src, Path("."), offline=True)
        self.assertEqual(entries, [])
        self.assertIn("--offline", err)


class ConfigTests(unittest.TestCase):
    def test_load_default(self):
        here = Path(__file__).resolve()
        project = here.parents[1]
        sources = load_sources(project / "pipeline" / "sources.toml")
        names = [s.name for s in sources]
        self.assertIn("antifilter-domains", names)
        self.assertIn("community-exclusions", names)
        excl = next(s for s in sources if s.name == "community-exclusions")
        self.assertEqual(excl.kind, "exclusions")


class RoundtripTests(unittest.TestCase):
    def test_jsonl_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "entries.jsonl"
            entry = Entry(value="example.com", kind="domain", tier="auto", flags=["heuristic:x"])
            save_entries([entry], path)
            loaded = load_entries(path)
            self.assertEqual(loaded[0].value, "example.com")
            self.assertEqual(loaded[0].flags, ["heuristic:x"])
            self.assertEqual(loaded[0].evidence, [])


class HeuristicTests(unittest.TestCase):
    def test_no_default_flags(self):
        entry = Entry(value="example.com")
        flag_heuristics(entry)
        self.assertEqual(entry.flags, [])


if __name__ == "__main__":
    unittest.main()
