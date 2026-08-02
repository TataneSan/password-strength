import io
import unittest
from contextlib import redirect_stdout

from password_strength.cli import main, score_password


class ScoreTests(unittest.TestCase):
    def test_common_is_zero(self):
        score, label, _ = score_password("password")
        self.assertEqual(score, 0)
        self.assertEqual(label, "very weak")

    def test_strong_password(self):
        score, label, _ = score_password("X7!k#29pQw$z")
        self.assertGreaterEqual(score, 80)

    def test_short_penalized(self):
        weak, _, _ = score_password("abc")
        good, _, _ = score_password("aBc!xYz9qR2#")
        self.assertLess(weak, good)

    def test_sequential_penalty(self):
        seq, _, fb = score_password("abcd1234")
        self.assertTrue(
            has_penalty := any("sequential" in f for f in fb), fb)
        self.assertLess(seq, 100)

    def test_repetition_penalty(self):
        _, _, fb = score_password("xxaaaaxyzq!")
        self.assertTrue(any("repeating" in f for f in fb), fb)


class CliTests(unittest.TestCase):
    def run_cli(self, argv, stdin=""):
        import sys
        out = io.StringIO()
        old = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(out):
                code = main(argv)
        finally:
            sys.stdin = old
        return code, out.getvalue()

    def test_args(self):
        code, out = self.run_cli(["hunter2"])
        self.assertEqual(code, 0)
        self.assertIn("/100", out)

    def test_stdin(self):
        code, out = self.run_cli(["-"], "abc123\nX7!k#29pQw$z\n")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("/100"), 2)

    def test_min_score_gate(self):
        code, _ = self.run_cli(["--min-score", "60", "-"], "abc123\n")
        self.assertEqual(code, 2)
        code, _ = self.run_cli(["--min-score", "60", "-"], "X7!k#29pQw$z\n")
        self.assertEqual(code, 0)

    def test_json(self):
        code, out = self.run_cli(["--json", "X7!k#29pQw$z"])
        self.assertEqual(code, 0)
        self.assertIn('"label": "very strong"', out)

    def test_empty_input(self):
        code, _ = self.run_cli([], "")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
