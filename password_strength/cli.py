"""Score password strength from the command line.

Heuristics-only estimator (no network calls, no dictionaries bundled):
length, character classes, repetition and sequential-character penalties,
plus a small built-in list of the most common weak passwords.

Scores are 0-100 with a label: very weak (<20), weak (20-39), fair (40-59),
strong (60-79), very strong (80+).

Exit codes:
    0  all passwords meet the threshold (default scoring mode)
    1  input/output or command-line error
    2  at least one password scores below --min-score (CI gate)
"""

from __future__ import annotations

import argparse
import json
import math
import sys

COMMON = {
    "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "iloveyou", "admin",
    "letmein", "welcome", "monkey", "dragon", "football", "sunshine",
    "000000", "azerty", "motdepasse",
}

LABELS = [
    (80, "very strong"),
    (60, "strong"),
    (40, "fair"),
    (20, "weak"),
    (0, "very weak"),
]


def char_classes(pw):
    return (
        any(c.islower() for c in pw)
        + any(c.isupper() for c in pw)
        + any(c.isdigit() for c in pw)
        + any(not c.isalnum() for c in pw)
    )


def has_sequential_run(pw, run=4):
    """True if a run of >= run ascending/descending characters exists."""
    streak = 1
    for prev, cur in zip(pw, pw[1:]):
        if abs(ord(cur) - ord(prev)) == 1:
            streak += 1
            if streak >= run:
                return True
        else:
            streak = 1
    return False


def has_repetition(pw, run=4):
    """True if the same character repeats run times in a row."""
    return any(pw[i:i + run] == pw[i] * run for i in range(len(pw) - run + 1))


def score_password(pw):
    """Return (score 0-100, label, list of feedback strings)."""
    feedback = []
    if pw.lower() in COMMON:
        return 0, "very weak", ["extremely common password"]

    score = 0
    n = len(pw)
    score += min(n * 4, 40)
    if n < 8:
        feedback.append("use at least 8 characters")

    classes = char_classes(pw)
    score += classes * 10
    if classes < 3:
        feedback.append("mix lowercase, uppercase, digits and symbols")

    # Bonus for entropy-like variety.
    distinct = len(set(pw))
    if n:
        score += int(10 * math.log2(max(distinct, 1)) / math.log2(32))

    if has_repetition(pw):
        score -= 15
        feedback.append("avoid repeating the same character")
    if has_sequential_run(pw):
        score -= 15
        feedback.append("avoid sequential runs like 'abcd' or '1234'")

    score = max(0, min(100, score))
    label = next(label for bound, label in LABELS if score >= bound)
    if score >= 80 and not feedback:
        feedback.append("good password")
    return score, label, feedback


def read_passwords(path):
    if path in (None, "-"):
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def build_parser():
    p = argparse.ArgumentParser(
        prog="password-strength",
        description="Score the strength of passwords read from stdin, a file "
                    "(one per line) or positional arguments. Nothing is "
                    "stored or sent anywhere; scoring is a local heuristic.",
    )
    p.add_argument("passwords", nargs="*",
                   help="passwords to score (omit to read from stdin; "
                        "'-' reads stdin explicitly)")
    p.add_argument("--file", metavar="FILE",
                   help="read one password per line from FILE")
    p.add_argument("--min-score", type=int, metavar="N", default=0,
                   help="exit 2 if any password scores below N (default 0)")
    p.add_argument("--feedback", action="store_true",
                   help="print one improvement hint line per password")
    p.add_argument("--json", action="store_true",
                   help="print a JSON report instead of plain text")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress per-password output; exit code only")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    pw_list = list(args.passwords)
    if args.file:
        try:
            pw_list.extend(x for x in read_passwords(args.file) if x != "")
        except OSError as exc:
            print("error: cannot read %s: %s" % (args.file, exc), file=sys.stderr)
            return 1
    if not pw_list or "-" in pw_list:
        pw_list = [x for x in pw_list if x != "-"]
        pw_list.extend(x for x in read_passwords("-") if x != "")
    if not pw_list:
        print("error: no password provided (stdin or arguments)",
              file=sys.stderr)
        return 1

    results = []
    weakest = 100
    for pw in pw_list:
        score, label, feedback = score_password(pw)
        weakest = min(weakest, score)
        results.append({
            "length": len(pw),
            "score": score,
            "label": label,
            "feedback": feedback,
        })

    ok = weakest >= args.min_score

    if args.json:
        print(json.dumps({
            "ok": ok,
            "count": len(results),
            "min_score_required": args.min_score,
            "weakest_score": weakest,
            "results": results,
        }, indent=2))
    elif not args.quiet:
        for r in results:
            print("%3d/100  %-11s  (%d chars)" % (r["score"], r["label"], r["length"]))
            if args.feedback:
                for hint in r["feedback"]:
                    print("    - %s" % hint)

    if not ok:
        print("error: weakest score %d below required %d"
              % (weakest, args.min_score), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
