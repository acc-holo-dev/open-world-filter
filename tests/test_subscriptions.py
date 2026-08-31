import unittest

from pipeline.subscriptions import (
    render_clash,
    render_manifest,
    render_site,
    render_v2rayn,
)


class ClashTests(unittest.TestCase):
    def test_structure(self):
        clash = render_clash("acc-holo-dev", "open-world-filter")
        providers = clash["rule-providers"]
        self.assertIn("owf-domains", providers)
        self.assertIn("owf-ips", providers)
        self.assertEqual(providers["owf-domains"]["behavior"], "domain")
        self.assertEqual(providers["owf-ips"]["behavior"], "ipcidr")
        self.assertIn("RULE-SET,owf-domains,PROXY", clash["rules"])
        self.assertIn("MATCH,DIRECT", clash["rules"])

    def test_urls_point_to_release(self):
        clash = render_clash("owner-x", "repo-y")
        url = clash["rule-providers"]["owf-ips"]["url"]
        self.assertTrue(url.startswith("https://github.com/owner-x/repo-y/releases/latest/download/"))
        self.assertTrue(url.endswith("owf-ips.lst"))


class V2raynTests(unittest.TestCase):
    def test_ext_references(self):
        snipped = render_v2rayn("acc-holo-dev", "open-world-filter")
        rules = snipped["routing"]["rules"]
        self.assertIn({"type": "field", "ip": ["ext:geoip.dat:owf"], "outboundTag": "proxy"}, rules)
        self.assertIn({"type": "field", "domain": ["ext:geosite.dat:owf"], "outboundTag": "proxy"}, rules)


class ManifestTests(unittest.TestCase):
    def test_all_clients_present(self):
        manifest = render_manifest("acc-holo-dev", "open-world-filter")
        expected = ["throne-full", "throne-minimal", "sing-box-config", "clash-meta",
                    "v2rayn-routing", "proxy-domains-srs", "proxy-ips-srs",
                    "geoip-dat", "geosite-dat", "geoip-db", "geosite-db"]
        for key in expected:
            self.assertIn(key, manifest["clients"], key)
        self.assertTrue(manifest["clients"]["throne-full"].endswith("route-profile-throne-full.json"))

    def test_category(self):
        manifest = render_manifest("o", "r", category="mycat")
        self.assertEqual(manifest["category"], "mycat")


class SiteTests(unittest.TestCase):
    def test_bilingual_links(self):
        html = render_site(render_manifest("acc-holo-dev", "open-world-filter"))
        self.assertIn("lang=\"ru\"", html)
        self.assertIn("Инструкции", html)
        self.assertIn("Instructions", html)
        self.assertIn("route-profile-throne-full.json", html)
        self.assertIn("https://github.com/acc-holo-dev/open-world-filter", html)


if __name__ == "__main__":
    unittest.main()
