package main

import (
	"strings"
	"testing"
)

func TestEmptyPassword(t *testing.T) {
	a := analyze("")
	if a.Score != 0 || a.EntropyBits != 0 {
		t.Fatalf("empty password: score=%d entropy=%.1f", a.Score, a.EntropyBits)
	}
}

func TestCommonPasswordIsVeryWeak(t *testing.T) {
	a := analyze("password")
	if a.Score > 0 {
		t.Fatalf("common password should score 0, got %d", a.Score)
	}
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "common passwords") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected common-password warning, got %v", a.Warnings)
	}
}

func TestStrongPassword(t *testing.T) {
	a := analyze("Tr0ub4dor&3x!Kp9z@Q")
	if a.Score < 3 {
		t.Fatalf("expected strong, got %d (%s)", a.Score, a.ScoreLabel)
	}
	if a.Length != 19 {
		t.Fatalf("length mismatch: %d", a.Length)
	}
	if len(a.CharsetFlags) != 4 {
		t.Fatalf("expected 4 classes, got %v", a.CharsetFlags)
	}
}

func TestCharsetDetection(t *testing.T) {
	cases := []struct {
		pw       string
		expected int
	}{
		{"abcdef", 1},
		{"ABCdef", 2},
		{"abc123", 2},
		{"aB1!", 4},
	}
	for _, c := range cases {
		a := analyze(c.pw)
		if len(a.CharsetFlags) != c.expected {
			t.Fatalf("%q: expected %d classes, got %v", c.pw, c.expected, a.CharsetFlags)
		}
	}
}

func TestSequencePenalty(t *testing.T) {
	baselineRaw := analyze("abcdefgh")   // has long sequence
	baselineNoSeq := analyze("azbvxsdw")  // scrambled
	if baselineRaw.EntropyBits >= baselineNoSeq.EntropyBits {
		t.Fatalf("sequence should reduce entropy (seq=%.1f vs no-seq=%.1f)", baselineRaw.EntropyBits, baselineNoSeq.EntropyBits)
	}
}

func TestRepeatPenalty(t *testing.T) {
	baseline := analyze("zzzzzzzz")
	scrambled := analyze("zqwrnbmx")
	if baseline.EntropyBits >= scrambled.EntropyBits {
		t.Fatalf("repeat should reduce entropy (rep=%.1f vs scr=%.1f)", baseline.EntropyBits, scrambled.EntropyBits)
	}
}

func TestShortPasswordWarning(t *testing.T) {
	a := analyze("A1!")
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "8 characters") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected short warning, got %v", a.Warnings)
	}
}

func TestHumanTime(t *testing.T) {
	cases := []struct {
		s        float64
		contains string
	}{
		{0.5, "instant"},
		{120, "minute"},
		{7200, "hour"},
		{172800, "day"},
		{31557600 * 5, "year"},
		{315576000 * 12, "century"},
	}
	for _, c := range cases {
		got := humanTime(c.s)
		if !strings.Contains(got, c.contains) {
			t.Fatalf("%.0fs: expected to contain %q, got %q", c.s, c.contains, got)
		}
	}
}

func TestMaskPassword(t *testing.T) {
	if maskPassword("ab") != "**" {
		t.Fatal(maskPassword("ab"))
	}
	if maskPassword("abc") != "a*c" {
		t.Fatal(maskPassword("abc"))
	}
	if maskPassword("password") != "p******d" {
		t.Fatal(maskPassword("password"))
	}
}

func TestScoreBands(t *testing.T) {
	cases := []struct {
		pw    string
		min   int
		max   int
	}{
		{"a", 0, 0},
		{"password", 0, 0},
		{"abc123", 0, 1},
		{"hunter2", 1, 2},
		{"correct horse battery staple", 3, 4},
		{"Xk#9$mQ2!pL&7@vN4%jK8+zR", 4, 4},
	}
	for _, c := range cases {
		a := analyze(c.pw)
		if a.Score < c.min || a.Score > c.max {
			t.Fatalf("%q: score=%d (entropy=%.1f), expected [%d,%d]", c.pw, a.Score, a.EntropyBits, c.min, c.max)
		}
	}
}

func TestLongestSequence(t *testing.T) {
	if n := longestSequence("abcd"); n != 4 {
		t.Fatalf("abcd: %d", n)
	}
	if n := longestSequence("azby"); n != 1 {
		t.Fatalf("azby: %d", n)
	}
	if n := longestSequence(""); n != 0 {
		t.Fatalf("empty: %d", n)
	}
}
