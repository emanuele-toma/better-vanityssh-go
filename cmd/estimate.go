package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/emanueletoma/better-vanityssh-go/display"
	"github.com/emanueletoma/better-vanityssh-go/keygen"
)

// numVariableKeyChars is the approximate number of random base64 characters
// in the variable portion of an ED25519 SSH public key.
// The wire format has a 19-byte fixed prefix; the remaining 32 random bytes
// contribute roughly 43 base64 characters.
const numVariableKeyChars = 43

// numFingerprintChars is the number of base64 chars in a SHA256 fingerprint.
// SHA256 produces 32 bytes → 43 base64 chars (base64 without padding).
const numFingerprintChars = 43

var (
	flagEstimateJobs     int
	flagEstimateDuration time.Duration
	flagEstimateMaxLen   int
)

var estimateCmd = &cobra.Command{
	Use:   "estimate",
	Short: "Show probability matrix for finding a vanity key",
	Long: `estimate benchmarks your CPU's key generation rate and prints a probability
matrix showing how long it would take to find a vanity SSH key for each string
length across three match strategies.

Match strategies:
  prefix/suffix  target string at a fixed position (anchored regex, e.g. ^abc or abc$)
  key contains   target string appears anywhere in the ~43 random public-key chars
  fp contains    target string appears anywhere in the 43 SHA256 fingerprint chars`,
	RunE: runEstimate,
}

func init() {
	estimateCmd.Flags().IntVarP(&flagEstimateJobs, "jobs", "j", 0, "number of parallel workers (default: number of CPUs)")
	estimateCmd.Flags().DurationVarP(&flagEstimateDuration, "duration", "d", 3*time.Second, "benchmark duration")
	estimateCmd.Flags().IntVarP(&flagEstimateMaxLen, "max-length", "m", 8, "maximum string length to show in the matrix (1-16)")
	rootCmd.AddCommand(estimateCmd)
}

func runEstimate(_ *cobra.Command, _ []string) error {
	numJobs := flagEstimateJobs
	if numJobs < 0 {
		return fmt.Errorf("--jobs must be non-negative, got %d", numJobs)
	}
	if numJobs == 0 {
		numJobs = runtime.NumCPU()
	}
	if flagEstimateMaxLen < 1 || flagEstimateMaxLen > 16 {
		return fmt.Errorf("--max-length must be between 1 and 16, got %d", flagEstimateMaxLen)
	}

	fmt.Fprintf(os.Stderr, "Benchmarking key generation (%s, %d thread(s))...\n",
		flagEstimateDuration.Round(time.Millisecond), numJobs)

	count, elapsed, err := benchmarkKeyRate(context.Background(), numJobs, flagEstimateDuration)
	if err != nil {
		return fmt.Errorf("benchmark: %w", err)
	}

	rate := float64(count) / elapsed.Seconds()
	fmt.Fprintf(os.Stderr, "Rate: %s keys/s\n\n", display.FormatCount(int64(rate)))

	printEstimateMatrix(rate, flagEstimateMaxLen)
	return nil
}

// benchmarkKeyRate generates keys for duration and returns the count and actual elapsed time.
func benchmarkKeyRate(ctx context.Context, numJobs int, duration time.Duration) (int64, time.Duration, error) {
	keygen.ResetCounters()

	// \x01 never appears in base64 output, so this regex never matches.
	neverMatch := regexp.MustCompile("\x01")

	bctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	results := make(chan keygen.Result, numJobs)
	g, gctx := errgroup.WithContext(bctx)

	start := time.Now()
	for range numJobs {
		g.Go(func() error {
			return keygen.FindKeys(gctx, keygen.Options{Regex: neverMatch}, results)
		})
	}
	if err := g.Wait(); err != nil {
		return 0, 0, err
	}
	return keygen.KeyCount(), time.Since(start), nil
}

// estimateStrategy describes one probability model for vanity key matching.
type estimateStrategy struct {
	name    string
	notes   []string
	probFn  func(length int) float64
}

// buildEstimateStrategies returns the set of match strategies to analyze.
func buildEstimateStrategies() []estimateStrategy {
	return []estimateStrategy{
		{
			name: "Prefix / Suffix  (fixed position)",
			notes: []string{
				"Anchored regex matches the start or end of the key or fingerprint",
				"Example regexes: ^abc  or  abc$",
				"P(match) = 1 / 64^length  (base64 alphabet has 64 symbols)",
			},
			probFn: func(n int) float64 {
				return math.Pow(1.0/64.0, float64(n))
			},
		},
		{
			name: "Contains in public key  (variable position)",
			notes: []string{
				fmt.Sprintf("Unanchored regex matches anywhere in ~%d random key chars", numVariableKeyChars),
				"Example regex: abc  (no anchors)",
				fmt.Sprintf("P(match) = 1 - (1 - 1/64^n)^(%d - n + 1)", numVariableKeyChars),
				"Note: the first ~25 base64 chars of an ED25519 key are a fixed prefix",
			},
			probFn: func(n int) float64 {
				positions := numVariableKeyChars - n + 1
				if positions <= 0 {
					return 0
				}
				p := math.Pow(1.0/64.0, float64(n))
				return 1.0 - math.Pow(1.0-p, float64(positions))
			},
		},
		{
			name: "Contains in fingerprint  (variable position, --fingerprint)",
			notes: []string{
				fmt.Sprintf("Unanchored regex matches anywhere in %d fingerprint chars", numFingerprintChars),
				"Example regex: abc  (with --fingerprint flag)",
				fmt.Sprintf("P(match) = 1 - (1 - 1/64^n)^(%d - n + 1)", numFingerprintChars),
				"SHA256 fingerprint is entirely random; all chars are variable",
			},
			probFn: func(n int) float64 {
				positions := numFingerprintChars - n + 1
				if positions <= 0 {
					return 0
				}
				p := math.Pow(1.0/64.0, float64(n))
				return 1.0 - math.Pow(1.0-p, float64(positions))
			},
		},
	}
}

// confidenceLevels are the probability thresholds shown in the matrix columns.
var confidenceLevels = [3]float64{0.50, 0.75, 0.90}

func printEstimateMatrix(rate float64, maxLen int) {
	const colW = 16
	headerFmt := "  %-6s  %-*s  %-*s  %-*s  %-*s"
	header := fmt.Sprintf(headerFmt, "Length", colW, "P(one key)", colW, "50%", colW, "75%", colW, "90%")
	sep := strings.Repeat("-", len(header))

	for _, s := range buildEstimateStrategies() {
		fmt.Printf("Strategy: %s\n", s.name)
		for _, note := range s.notes {
			fmt.Printf("  %s\n", note)
		}
		fmt.Println()
		fmt.Println(header)
		fmt.Println(sep)

		for n := 1; n <= maxLen; n++ {
			p := s.probFn(n)
			if p <= 0 {
				fmt.Printf("  %-6d  %-*s  %-*s  %-*s  %-*s\n",
					n, colW, "impossible", colW, "-", colW, "-", colW, "-")
				continue
			}
			t50 := formatEstimateTime(estimateKeysNeeded(p, 0.50) / rate)
			t75 := formatEstimateTime(estimateKeysNeeded(p, 0.75) / rate)
			t90 := formatEstimateTime(estimateKeysNeeded(p, 0.90) / rate)
			fmt.Printf("  %-6d  %-*s  %-*s  %-*s  %-*s\n",
				n, colW, formatInvProb(p), colW, t50, colW, t75, colW, t90)
		}
		fmt.Println()
	}
}

// estimateKeysNeeded returns the number of keys needed to reach the given confidence level.
// Uses the geometric distribution CDF: P(X <= k) = 1 - (1-p)^k = confidence.
func estimateKeysNeeded(p, confidence float64) float64 {
	if p >= 1 {
		return 1
	}
	return math.Log(1-confidence) / math.Log(1-p)
}

// formatEstimateTime formats a duration given in seconds into a human-readable string.
func formatEstimateTime(seconds float64) string {
	switch {
	case seconds < 1:
		return "< 1 second"
	case seconds < 60:
		n := math.Round(seconds)
		if n == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%.0f seconds", n)
	case seconds < 3600:
		n := math.Round(seconds / 60)
		if n == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%.0f minutes", n)
	case seconds < 86400:
		return fmt.Sprintf("%.1f hours", seconds/3600)
	case seconds < 365.25*86400:
		return fmt.Sprintf("%.0f days", seconds/86400)
	default:
		return fmt.Sprintf("%.1f years", seconds/(365.25*86400))
	}
}

// formatInvProb formats a probability p as "1/N" using K/M/B/T/Q suffixes.
func formatInvProb(p float64) string {
	inv := 1.0 / p
	switch {
	case inv < 1_000:
		return fmt.Sprintf("1/%.0f", inv)
	case inv < 1_000_000:
		return fmt.Sprintf("1/%.1fK", inv/1_000)
	case inv < 1_000_000_000:
		return fmt.Sprintf("1/%.1fM", inv/1_000_000)
	case inv < 1_000_000_000_000:
		return fmt.Sprintf("1/%.1fB", inv/1_000_000_000)
	case inv < 1_000_000_000_000_000:
		return fmt.Sprintf("1/%.1fT", inv/1_000_000_000_000)
	default:
		return fmt.Sprintf("1/%.2e", inv)
	}
}
