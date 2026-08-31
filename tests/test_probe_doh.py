import unittest

from pipeline.probe import parse_doh_json


class DoHParseTests(unittest.TestCase):
    def test_nxdomain(self):
        r = parse_doh_json({"Status": 3, "Answer": []})
        self.assertEqual(r["rcode"], "NXDOMAIN")
        self.assertEqual(r["ips"], [])

    def test_alive_only_a(self):
        r = parse_doh_json({
            "Status": 0,
            "Answer": [
                {"type": 1, "data": "1.2.3.4"},
                {"type": 5, "data": "cname.example."},   # CNAME не считается
                {"type": 1, "data": "5.6.7.8"},
            ],
        })
        self.assertEqual(r["rcode"], "NOERROR")
        self.assertEqual(r["ips"], ["1.2.3.4", "5.6.7.8"])

    def test_empty(self):
        r = parse_doh_json({"Status": 0, "Answer": []})
        self.assertEqual(r["rcode"], "NOERROR")
        self.assertEqual(r["ips"], [])

    def test_servfail_is_error(self):
        r = parse_doh_json({"Status": 2})
        self.assertEqual(r["rcode"], "ERROR")

    def test_garbage_status(self):
        r = parse_doh_json({"Status": "zzz"})
        self.assertEqual(r["rcode"], "ERROR")


if __name__ == "__main__":
    unittest.main()
