package cmd

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/emanueletoma/better-vanityssh-go/display"
	"github.com/emanueletoma/better-vanityssh-go/keygen"
)

// tuneBatchRounds is the number of independent measurements taken per batch
// size. The median is used to reject OS-scheduling outliers.
const tuneBatchRounds = 3

var (
	flagTuneBatchJobs     int
	flagTuneBatchDuration time.Duration
)

var tuneBatchCmd = &cobra.Command{
	Use:   "tune-batch",
	Short: "Find the optimal batch size for your CPU",
	Long: `tune-batch benchmarks key generation across a range of batch sizes and
reports which value produces the highest throughput on your hardware.

The batch size controls how many ED25519 points are compressed together per
iteration using Montgomery's batch inversion trick. Larger batches amortize
the expensive field inversion over more keys, but eventually cause cache
pressure. The optimal value is CPU- and system-specific.

Each candidate is measured tuneBatchRounds times (median eliminates OS jitter).
The sweep tests powers of two from 2 to 512, then re-runs the top candidate
with a longer measurement to confirm the result.

Use the reported --batch-size value with the main vanityssh command.`,
	RunE: runTuneBatch,
}

func init() {
	tuneBatchCmd.Flags().IntVarP(&flagTuneBatchJobs, "jobs", "j", 0, "number of parallel workers (default: number of CPUs)")
	tuneBatchCmd.Flags().DurationVarP(&flagTuneBatchDuration, "duration", "d", time.Second, "benchmark duration per round per batch size")
	rootCmd.AddCommand(tuneBatchCmd)
}

// batchSizeResult holds the throughput measurement for a single batch size.
type batchSizeResult struct {
	size int
	rate float64 // median keys per second across rounds
}

func runTuneBatch(_ *cobra.Command, _ []string) error {
	numJobs := flagTuneBatchJobs
	if numJobs < 0 {
		return fmt.Errorf("--jobs must be non-negative, got %d", numJobs)
	}
	if numJobs == 0 {
		numJobs = runtime.NumCPU()
	}

	// Candidate batch sizes: powers of 2 from 2 to 512.
	candidates := []int{2, 4, 8, 16, 32, 64, 128, 256, 512}

	totalDuration := flagTuneBatchDuration * time.Duration(tuneBatchRounds) * time.Duration(len(candidates))
	fmt.Fprintf(os.Stderr, "Tuning batch size (%d rounds × %s per size, %d worker(s), ~%s total)...\n\n",
		tuneBatchRounds, flagTuneBatchDuration.Round(time.Millisecond),
		numJobs, totalDuration.Round(time.Second))

	// Warm-up: long enough for CPU frequency scaling to settle.
	if err := warmUpWorkers(numJobs, 500*time.Millisecond); err != nil {
		return fmt.Errorf("warm-up: %w", err)
	}

	results, err := sweepBatchSizes(numJobs, candidates, flagTuneBatchDuration)
	if err != nil {
		return err
	}

	// Find the best candidate from the sweep.
	best := results[0]
	for _, r := range results[1:] {
		if r.rate > best.rate {
			best = r
		}
	}

	// Re-run the winner with 3× the duration per round to tighten the final number.
	fmt.Fprintf(os.Stderr, "Confirming batch=%d with longer run...\r", best.size)
	confirmed, err := medianBatchRate(context.Background(), numJobs, best.size, flagTuneBatchDuration*3, tuneBatchRounds)
	if err != nil {
		return fmt.Errorf("confirm best: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%*s\r", 50, "")
	best.rate = confirmed

	printTuneTable(results, best.size)

	fmt.Printf("\nBest batch size: %d (%s keys/s)\n", best.size, display.FormatCount(int64(best.rate)))
	fmt.Printf("Add --batch-size %d to your vanityssh command for optimal performance.\n", best.size)
	return nil
}

// sweepBatchSizes benchmarks each candidate batch size and returns results in order.
// Each size is measured tuneBatchRounds times; the median is stored.
func sweepBatchSizes(numJobs int, candidates []int, duration time.Duration) ([]batchSizeResult, error) {
	results := make([]batchSizeResult, 0, len(candidates))
	for i, size := range candidates {
		fmt.Fprintf(os.Stderr, "  [%d/%d] batch=%-4d  round 0/%d\r",
			i+1, len(candidates), size, tuneBatchRounds)
		rate, err := medianBatchRate(context.Background(), numJobs, size, duration, tuneBatchRounds)
		if err != nil {
			return nil, fmt.Errorf("benchmark batch=%d: %w", size, err)
		}
		results = append(results, batchSizeResult{size: size, rate: rate})
	}
	// Clear the progress line.
	fmt.Fprintf(os.Stderr, "%*s\r", 55, "")
	return results, nil
}

// medianBatchRate runs key generation with the given batch size for rounds
// independent measurements of duration each and returns the median keys/s.
// Using the median instead of a single run rejects OS-scheduling outliers.
func medianBatchRate(ctx context.Context, numJobs, batchSize int, duration time.Duration, rounds int) (float64, error) {
	rates := make([]float64, 0, rounds)
	for range rounds {
		r, err := benchmarkSingleBatch(ctx, numJobs, batchSize, duration)
		if err != nil {
			return 0, err
		}
		rates = append(rates, r.rate)
	}
	return medianFloat(rates), nil
}

// benchmarkSingleBatch runs key generation with the given batch size for duration
// and returns the measured throughput.
func benchmarkSingleBatch(ctx context.Context, numJobs, batchSize int, duration time.Duration) (batchSizeResult, error) {
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
			return keygen.FindKeys(gctx, keygen.Options{
				Regex:     neverMatch,
				BatchSize: batchSize,
			}, results)
		})
	}
	if err := g.Wait(); err != nil {
		return batchSizeResult{}, err
	}

	count := keygen.KeyCount()
	elapsed := time.Since(start)
	rate := float64(count) / elapsed.Seconds()
	return batchSizeResult{size: batchSize, rate: rate}, nil
}

// warmUpWorkers runs a brief no-op benchmark to prime CPU caches and let
// frequency scaling settle before measurements begin.
func warmUpWorkers(numJobs int, duration time.Duration) error {
	_, err := benchmarkSingleBatch(context.Background(), numJobs, keygen.DefaultBatchSize, duration)
	return err
}

// medianFloat returns the median of a slice of float64 values.
func medianFloat(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := make([]float64, len(xs))
	copy(sorted, xs)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// printTuneTable prints a formatted table of sweep results.
func printTuneTable(results []batchSizeResult, bestSize int) {
	// Find the peak rate for speedup calculation.
	var peakRate float64
	for _, r := range results {
		if r.rate > peakRate {
			peakRate = r.rate
		}
	}

	fmt.Printf("  %-8s  %-14s  %-8s\n", "Batch", "Keys/s", "Speedup")
	fmt.Printf("  %-8s  %-14s  %-8s\n", "-----", "------", "-------")
	for _, r := range results {
		marker := "  "
		if r.size == keygen.DefaultBatchSize {
			marker = "D "
		}
		if r.size == bestSize {
			marker = "* "
		}
		speedup := r.rate / peakRate
		fmt.Printf("  %s%-6d  %-14s  %.2fx\n",
			marker, r.size, display.FormatCount(int64(r.rate))+"/s", speedup)
	}
	fmt.Printf("\n  D = default  * = best\n")
}
