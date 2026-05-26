package cmd

import (
	"math"
	"strings"
	"testing"
)

func TestFormatEstimateTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		seconds float64
		want    string
	}{
		{name: "zero", seconds: 0, want: "< 1 second"},
		{name: "fractional", seconds: 0.5, want: "< 1 second"},
		{name: "exactly 1", seconds: 1, want: "1 second"},
		{name: "2 seconds", seconds: 2, want: "2 seconds"},
		{name: "59 seconds", seconds: 59, want: "59 seconds"},
		{name: "exactly 1 minute", seconds: 60, want: "1 minute"},
		{name: "2 minutes", seconds: 120, want: "2 minutes"},
		{name: "90 seconds rounds to 2 minutes", seconds: 90, want: "2 minutes"},
		{name: "59.4 minutes still minutes", seconds: 59.4 * 60, want: "59 minutes"},
		{name: "1 hour", seconds: 3600, want: "1.0 hours"},
		{name: "23.9 hours", seconds: 23.9 * 3600, want: "23.9 hours"},
		{name: "1 day", seconds: 86400, want: "1 days"},
		{name: "364 days", seconds: 364 * 86400, want: "364 days"},
		{name: "1 year", seconds: 365.25 * 86400, want: "1.0 years"},
		{name: "10 years", seconds: 10 * 365.25 * 86400, want: "10.0 years"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatEstimateTime(tt.seconds)
			if got != tt.want {
				t.Errorf("formatEstimateTime(%v) = %q, want %q", tt.seconds, got, tt.want)
			}
		})
	}
}

func TestFormatInvProb(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		p    float64
		want string
	}{
		{name: "1/64", p: 1.0 / 64, want: "1/64"},
		{name: "1/999", p: 1.0 / 999, want: "1/999"},
		{name: "1/1000", p: 1.0 / 1000, want: "1/1.0K"},
		{name: "1/4096", p: 1.0 / 4096, want: "1/4.1K"},
		{name: "1/million", p: 1e-6, want: "1/1.0M"},
		{name: "1/2billion", p: 1.0 / 2_000_000_000, want: "1/2.0B"},
		{name: "1/trillion", p: 1e-12, want: "1/1.0T"},
		{name: "very small", p: 1e-18, want: "1/1.00e+18"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatInvProb(tt.p)
			if got != tt.want {
				t.Errorf("formatInvProb(%v) = %q, want %q", tt.p, got, tt.want)
			}
		})
	}
}

func TestEstimateKeysNeeded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		p          float64
		confidence float64
		wantAbout  float64 // expected value within 1%
	}{
		{
			name:       "p=0.5 50% confidence needs 1 key",
			p:          0.5,
			confidence: 0.50,
			wantAbout:  1.0,
		},
		{
			name:       "p=0.5 75% confidence needs 2 keys",
			p:          0.5,
			confidence: 0.75,
			wantAbout:  2.0,
		},
		{
			name:       "p=1 always 1 key",
			p:          1.0,
			confidence: 0.99,
			wantAbout:  1.0,
		},
		{
			// For small p: k ≈ -ln(1-c)/p. At c=0.5, k ≈ 0.693/p.
			name:       "small p 50% confidence",
			p:          1e-6,
			confidence: 0.50,
			wantAbout:  math.Log(2) / 1e-6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := estimateKeysNeeded(tt.p, tt.confidence)
			ratio := got / tt.wantAbout
			if ratio < 0.99 || ratio > 1.01 {
				t.Errorf("estimateKeysNeeded(%v, %v) = %v, want ~%v (ratio %.4f)",
					tt.p, tt.confidence, got, tt.wantAbout, ratio)
			}
		})
	}
}

func TestBuildEstimateStrategies_ProbabilityProperties(t *testing.T) {
	t.Parallel()
	strategies := buildEstimateStrategies()

	if len(strategies) == 0 {
		t.Fatal("buildEstimateStrategies returned empty slice")
	}

	for _, s := range strategies {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			// Probability must decrease (or stay) as length increases.
			prev := s.probFn(1)
			for n := 2; n <= 8; n++ {
				p := s.probFn(n)
				if p > prev {
					t.Errorf("length %d: probability %v > previous %v (should not increase)", n, p, prev)
				}
				prev = p
			}

			// Single-char probability must be > 0 and <= 1.
			p1 := s.probFn(1)
			if p1 <= 0 || p1 > 1 {
				t.Errorf("length 1: probability = %v, want (0,1]", p1)
			}

			// Contains strategies must give higher probability than 1/64 (prefix) for short lengths.
			if strings.Contains(s.name, "Contains") {
				if p1 <= 1.0/64.0 {
					t.Errorf("contains strategy length 1: probability %v should exceed 1/64 = %v", p1, 1.0/64.0)
				}
			}

			// Very long lengths beyond variable chars should return 0.
			if strings.Contains(s.name, "Contains") {
				longP := s.probFn(100)
				if longP != 0 {
					t.Errorf("length 100: expected 0 probability for contains match, got %v", longP)
				}
			}
		})
	}
}

// saveEstimateFlags saves estimate-subcommand flag values and restores them on cleanup.
func saveEstimateFlags(t *testing.T) {
	t.Helper()
	origJobs := flagEstimateJobs
	origDuration := flagEstimateDuration
	origMaxLen := flagEstimateMaxLen
	t.Cleanup(func() {
		flagEstimateJobs = origJobs
		flagEstimateDuration = origDuration
		flagEstimateMaxLen = origMaxLen
		rootCmd.SetArgs(nil)
	})
}

func TestEstimate_FlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{
			name:    "negative jobs",
			args:    []string{"estimate", "--jobs", "-1"},
			wantSub: "--jobs must be non-negative",
		},
		{
			name:    "max-length too low",
			args:    []string{"estimate", "--max-length", "0"},
			wantSub: "--max-length must be between 1 and 16",
		},
		{
			name:    "max-length too high",
			args:    []string{"estimate", "--max-length", "17"},
			wantSub: "--max-length must be between 1 and 16",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveEstimateFlags(t)
			rootCmd.SetArgs(tt.args)
			captureStderr(t, func() {
				err := rootCmd.Execute()
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
				}
			})
		})
	}
}

func TestEstimate_OutputContainsStrategies(t *testing.T) {
	saveEstimateFlags(t)
	rootCmd.SetArgs([]string{"estimate", "--duration", "200ms", "--jobs", "1", "--max-length", "3"})

	var stdout, stderr string
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("Execute error: %v", err)
			}
		})
	})

	// Stderr must have benchmark output.
	if !strings.Contains(stderr, "keys/s") {
		t.Errorf("stderr missing rate: %q", stderr)
	}

	// Stdout must contain all three strategy names.
	for _, want := range []string{"Prefix", "Suffix", "Contains", "fingerprint"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, stdout)
		}
	}

	// Data rows start with "  N " where N is the length. Check rows 1-3 are present
	// and row 4 is absent. We test for the start-of-line pattern to avoid false
	// positives from "4" appearing inside time or probability column values.
	for _, n := range []string{"1", "2", "3"} {
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, " "), n+" ") && strings.HasPrefix(line, "  ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stdout missing data row for length %s; got:\n%s", n, stdout)
		}
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "4 ") && strings.HasPrefix(line, "  ") {
			t.Errorf("stdout contains unexpected length 4 row: %q", line)
		}
	}
}
