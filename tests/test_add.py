import tempfile
import unittest
from pathlib import Path

from pipeline.__main__ import build_parser, cmd_add


class AddCommandTests(unittest.TestCase):
    def test_add_appends_dedupes_and_rejects(self):
        # Команда есть в CLI
        args = build_parser().parse_args(["добавить", "Example.COM"])
        self.assertEqual(args.command, "добавить")
        self.assertEqual(args.value, "Example.COM")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # первый вызов: трим + lowercase + чистый appending
            self.assertEqual(cmd_add(args, root, None, None), 0)
            path = root / "community" / "additions.txt"
            self.assertEqual(path.read_text(encoding="utf-8").splitlines(), ["example.com"])
            # повторный вызов: «уже в списке», дубликата нет
            self.assertEqual(cmd_add(args, root, None, None), 0)
            self.assertEqual(path.read_text(encoding="utf-8").splitlines(), ["example.com"])
            # мусор отклоняется с ненулевым кодом, файл не трогается
            bad = build_parser().parse_args(["добавить", "not a domain!!"])
            self.assertEqual(cmd_add(bad, root, None, None), 2)
            self.assertEqual(path.read_text(encoding="utf-8").splitlines(), ["example.com"])


if __name__ == "__main__":
    unittest.main()