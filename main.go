// password-strength analyzes password entropy and reports a strength score
// with human-readable time-to-crack estimates.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
)

type analysis struct {
	Password          string   `json:"-"`
	Length            int      `json:"length"`
	CharsetSize       int      `json:"charset_size"`
	CharsetFlags      []string `json:"character_classes"`
	EntropyBits       float64  `json:"entropy_bits"`
	Score             int      `json:"score"` // 0-4
	ScoreLabel        string   `json:"score_label"`
	GuessesLog10      float64  `json:"guesses_log10"`
	CrackTimesSeconds crackTimes `json:"crack_times_seconds"`
	Warnings          []string `json:"warnings,omitempty"`
	Suggestions       []string `json:"suggestions,omitempty"`
}

type crackTimes struct {
	OnlineThrottled100PerHour float64 `json:"online_throttled_100_per_hour"`
	OnlineUnthrottled10PerSec float64 `json:"online_unthrottled_10_per_sec"`
	OfflineSlowHash1e4PerSec  float64 `json:"offline_slow_hash_1e4_per_sec"`
	OfflineFastHash1e10PerSec float64 `json:"offline_fast_hash_1e10_per_sec"`
}

// Common passwords (small subset mirror of SecLists top entries).
var commonPasswords = map[string]bool{
	"password": true, "123456": true, "123456789": true, "qwerty": true,
	"abc123": true, "football": true, "monkey": true, "letmein": true,
	"dragon": true, "111111": true, "baseball": true, "iloveyou": true,
	"trustno1": true, "sunshine": true, "master": true, "welcome": true,
	"shadow": true, "ashley": true, "michael": true, "admin": true,
	"password1": true, "12345678": true, "123123": true, "root": true,
	"passw0rd": true, "superman": true, "princess": true, "batman": true,
}

var commonSequences = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"zyxwvutsrqponmlkjihgfedcba",
	"0123456789",
	"9876543210",
	"qwertyuiop", "asdfghjkl", "zxcvbnm",
}

func analyze(pw string) analysis {
	a := analysis{Password: pw, Length: len([]rune(pw))}
	classes := []string{}

	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	charset := 0
	if hasLower {
		charset += 26
		classes = append(classes, "lowercase")
	}
	if hasUpper {
		charset += 26
		classes = append(classes, "uppercase")
	}
	if hasDigit {
		charset += 10
		classes = append(classes, "digits")
	}
	if hasSymbol {
		charset += 33
		classes = append(classes, "symbols")
	}
	a.CharsetSize = charset
	a.CharsetFlags = classes

	// Raw entropy: log2(charset^length)
	if a.Length > 0 && charset > 0 {
		raw := float64(a.Length) * math.Log2(float64(charset))
		a.EntropyBits = raw
	}
	a.GuessesLog10 = a.EntropyBits / math.Log2(10)

	// Penalties
	lowered := strings.ToLower(pw)
	if commonPasswords[lowered] {
		a.EntropyBits = math.Min(a.EntropyBits, 10)
		a.Warnings = append(a.Warnings, "this password is in the top common passwords list")
	}
	if n := longestSequence(lowered); n >= 4 {
		a.EntropyBits *= 0.6
		a.Warnings = append(a.Warnings, fmt.Sprintf("contains a sequential pattern of %d chars", n))
	}
	if n := longestRepeat(pw); n >= 3 {
		a.EntropyBits *= 0.7
		a.Warnings = append(a.Warnings, fmt.Sprintf("contains a repeated character %d times in a row", n))
	}
	if a.Length < 8 {
		a.Warnings = append(a.Warnings, "shorter than 8 characters")
	}
	if len(classes) < 3 {
		a.Suggestions = append(a.Suggestions, "mix uppercase, lowercase, digits and symbols")
	}
	if a.Length < 12 {
		a.Suggestions = append(a.Suggestions, "use at least 12 characters")
	}

	// recalc log10 from adjusted entropy
	a.GuessesLog10 = a.EntropyBits / math.Log2(10)

	// Score mapping (zxcvbn-ish)
	switch {
	case a.EntropyBits < 28:
		a.Score, a.ScoreLabel = 0, "very weak"
	case a.EntropyBits < 36:
		a.Score, a.ScoreLabel = 1, "weak"
	case a.EntropyBits < 60:
		a.Score, a.ScoreLabel = 2, "fair"
	case a.EntropyBits < 80:
		a.Score, a.ScoreLabel = 3, "strong"
	default:
		a.Score, a.ScoreLabel = 4, "very strong"
	}

	guesses := math.Pow(10, a.GuessesLog10)
	a.CrackTimesSeconds = crackTimes{
		OnlineThrottled100PerHour: guesses / 100 * 3600,
		OnlineUnthrottled10PerSec: guesses / 10,
		OfflineSlowHash1e4PerSec:  guesses / 1e4,
		OfflineFastHash1e10PerSec: guesses / 1e10,
	}
	return a
}

func longestSequence(s string) int {
	if len(s) < 2 {
		return 0
	}
	best := 1
	cur := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 1
		}
	}
	return best
}

func longestRepeat(s string) int {
	if len(s) == 0 {
		return 0
	}
	best := 1
	cur := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 1
		}
	}
	return best
}

func humanTime(seconds float64) string {
	if math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return "unknown"
	}
	if seconds < 1 {
		return "instant"
	}
	units := []struct {
		name  string
		value float64
	}{
		{"century", 100 * 365.25 * 24 * 3600},
		{"year", 365.25 * 24 * 3600},
		{"month", 30.4 * 24 * 3600},
		{"day", 24 * 3600},
		{"hour", 3600},
		{"minute", 60},
		{"second", 1},
	}
	for _, u := range units {
		if seconds >= u.value {
			v := seconds / u.value
			plural := ""
			if v >= 2 {
				plural = "s"
			}
			return fmt.Sprintf("%.1f %s%s", v, u.name, plural)
		}
	}
	return "instant"
}

func main() {
	jsonOut := flag.Bool("json", false, "emit JSON output")
	verbose := flag.Bool("v", false, "include warnings and suggestions in text output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "password-strength — entropy + time-to-crack reports for passwords\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  password-strength [flags] <password> [password2 ...]\n")
		fmt.Fprintf(os.Stderr, "  echo \"hunter2\" | password-strength\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var inputs []string
	if flag.NArg() > 0 {
		inputs = flag.Args()
	} else {
		var buf []byte
		readBuf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(readBuf)
			buf = append(buf, readBuf[:n]...)
			if err != nil {
				break
			}
		}
		for _, l := range strings.Split(string(buf), "\n") {
			if s := strings.TrimSpace(l); s != "" {
				inputs = append(inputs, s)
			}
		}
	}
	if len(inputs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	results := make([]analysis, 0, len(inputs))
	for _, pw := range inputs {
		results = append(results, analyze(pw))
	}

	if *jsonOut {
		type outRow struct {
			Index    int      `json:"index"`
			Analysis analysis `json:"analysis"`
		}
		out := make([]outRow, len(results))
		for i, r := range results {
			out[i] = outRow{Index: i, Analysis: r}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	for _, r := range results {
		masked := maskPassword(r.Password)
		bar := scoreBar(r.Score)
		fmt.Printf("%s\n", masked)
		fmt.Printf("  %s %s  (%.1f bits entropy, %d chars, %d-class charset = %d)\n",
			bar, r.ScoreLabel, r.EntropyBits, r.Length, len(r.CharsetFlags), r.CharsetSize)
		fmt.Printf("  Crack time: online-throttled %s, offline-fast %s\n",
			humanTime(r.CrackTimesSeconds.OnlineThrottled100PerHour),
			humanTime(r.CrackTimesSeconds.OfflineFastHash1e10PerSec))
		if *verbose {
			for _, w := range r.Warnings {
				fmt.Printf("  ⚠  %s\n", w)
			}
			for _, s := range r.Suggestions {
				fmt.Printf("  ℹ  %s\n", s)
			}
		}
		fmt.Println()
	}
}

func maskPassword(pw string) string {
	r := []rune(pw)
	if len(r) <= 2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[0]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1])
}

func scoreBar(score int) string {
	filled := strings.Repeat("█", score+1)
	empty := strings.Repeat("░", 5-score-1)
	return "[" + filled + empty + "]"
}
