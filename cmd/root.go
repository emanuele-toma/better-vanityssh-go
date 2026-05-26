package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/emanueletoma/better-vanityssh-go/display"
	"github.com/emanueletoma/better-vanityssh-go/keygen"
)

var (
	flagFingerprint bool
	flagContinuous  bool
	flagJobs        int
	flagBatchSize   int
	flagOutput      string
	flagPassphrase  string
	flagCheckpoint  string
)

var rootCmd = &cobra.Command{
	Use:   "vanityssh <regex>",
	Short: "Generate ED25519 SSH keys with vanity public keys",
	Long: `vanityssh generates ED25519 SSH key pairs at high speed and matches
the resulting public keys (or SHA256 fingerprints) against a regex pattern.

On first match, the key pair is written to id_ed25519 and id_ed25519.pub
in the current directory. Use --continuous to keep finding keys.

When piping, only the private key is written to stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: run,
}

func init() {
	rootCmd.Flags().BoolVarP(&flagFingerprint, "fingerprint", "f", false, "match against SHA256 fingerprint instead of public key")
	rootCmd.Flags().BoolVarP(&flagContinuous, "continuous", "c", false, "keep finding keys after a match")
	rootCmd.Flags().IntVarP(&flagJobs, "jobs", "j", 0, "number of parallel workers (default: number of CPUs)")
	rootCmd.Flags().IntVarP(&flagBatchSize, "batch-size", "b", 0, "seeds read from crypto/rand per loop iteration (default: 64; use 'tune-batch' to find optimal)")
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "directory to save key files (default: current directory)")
	rootCmd.Flags().StringVarP(&flagPassphrase, "passphrase", "p", "", "derive deterministic seed via Argon2id (enables reproducible key generation)")
	rootCmd.Flags().StringVarP(&flagCheckpoint, "checkpoint", "C", "", "checkpoint file path for saving/resuming progress (requires --passphrase)")
}

// SetVersion sets the version string for the root command.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func run(_ *cobra.Command, args []string) error {
	if flagCheckpoint != "" && flagPassphrase == "" {
		return fmt.Errorf("--checkpoint requires --passphrase")
	}

	if flagOutput != "" {
		if err := os.MkdirAll(flagOutput, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	re, err := regexp.Compile(args[0])
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}

	display.Init()
	defer display.Reset()

	startTime := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Clean up terminal on interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	numJobs := flagJobs
	if numJobs < 0 {
		return fmt.Errorf("--jobs must be non-negative, got %d", numJobs)
	}
	if numJobs == 0 {
		numJobs = runtime.NumCPU()
	}

	if flagBatchSize < 0 {
		return fmt.Errorf("--batch-size must be non-negative, got %d", flagBatchSize)
	}

	opts := keygen.Options{
		Regex:       re,
		Fingerprint: flagFingerprint,
		BatchSize:   flagBatchSize,
	}

	if flagPassphrase != "" {
		fmt.Fprintf(os.Stderr, "Deriving key from passphrase...\n")
		opts.DerivedSeed = keygen.DeriveSeed(flagPassphrase)
	}

	if flagPassphrase != "" && flagCheckpoint != "" {
		idx, err := keygen.LoadCheckpoint(flagCheckpoint)
		if err != nil {
			return fmt.Errorf("load checkpoint: %w", err)
		}
		if idx > 0 {
			keygen.SetDetermIndex(idx)
			fmt.Fprintf(os.Stderr, "Resuming from key index %s\n", display.FormatCount(idx))
		}
	}

	results := make(chan keygen.Result, numJobs)
	g, gctx := errgroup.WithContext(ctx)

	// Launch workers
	for range numJobs {
		g.Go(func() error {
			return keygen.FindKeys(gctx, opts, results)
		})
	}

	// Checkpoint saver: only active in deterministic mode with a checkpoint file.
	if flagPassphrase != "" && flagCheckpoint != "" {
		g.Go(func() error {
			return keygen.RunCheckpointSaver(gctx, flagCheckpoint)
		})
	}

	// Result consumer
	g.Go(func() error {
		var matchNum int
		for {
			select {
			case r := <-results:
				matchNum++
				if err := handleResult(r, matchNum); err != nil {
					return err
				}
				if !flagContinuous {
					cancel()
					return nil
				}
			case <-gctx.Done():
				return nil
			}
		}
	})

	// Status bar updater
	g.Go(func() error {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if display.IsTTY() {
					count := keygen.KeyCount()
					elapsed := time.Since(startTime)
					rate := int64(float64(count) / elapsed.Seconds())
					matches := keygen.MatchCount()

					var status string
					if flagPassphrase != "" {
						status = fmt.Sprintf("Keys: %s | Index: %s | Rate: %s/s | Matches: %d | Elapsed: %s | Ctrl+C to exit",
							display.FormatCount(count), display.FormatCount(keygen.DetermIndex()),
							display.FormatCount(rate), matches, elapsed.Truncate(time.Second))
					} else {
						status = fmt.Sprintf("Keys: %s | Rate: %s/s | Matches: %d | Elapsed: %s | Ctrl+C to exit",
							display.FormatCount(count), display.FormatCount(rate), matches,
							elapsed.Truncate(time.Second))
					}
					display.UpdateStatusBar(status)
				}
			case <-gctx.Done():
				return nil
			}
		}
	})

	return g.Wait()
}

func handleResult(r keygen.Result, matchNum int) error {
	outDir := flagOutput
	if outDir == "" {
		outDir = "."
	}

	if flagContinuous {
		// Continuous mode: show match in scroll region (stderr) + stream PEM to stdout.
		if display.IsTTY() {
			display.PrintAboveStatus("--- Match #%d ---", matchNum)
			for line := range strings.SplitSeq(strings.TrimSpace(string(r.PrivateKeyPEM)), "\n") {
				display.PrintAboveStatus("%s", line)
			}
			display.PrintAboveStatus("%s", r.AuthorizedKey)
			display.PrintAboveStatus("SHA256:%s", r.Fingerprint)
		}
		fmt.Printf("%s", r.PrivateKeyPEM)
		privPath := filepath.Join(outDir, fmt.Sprintf("id_ed25519_%d", matchNum))
		pubPath := privPath + ".pub"
		if err := os.WriteFile(privPath, r.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(r.AuthorizedKey), 0644); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}
		return nil
	}

	// Single-match mode: tear down scroll region, print final output, write files.
	if display.IsTTY() {
		display.Reset()
		fmt.Printf("%s", r.PrivateKeyPEM)
		fmt.Printf("%s\n", r.AuthorizedKey)
		fmt.Printf("SHA256:%s\n", r.Fingerprint)
	} else {
		fmt.Printf("%s", r.PrivateKeyPEM)
	}
	privPath := filepath.Join(outDir, "id_ed25519")
	pubPath := filepath.Join(outDir, "id_ed25519.pub")
	if err := os.WriteFile(privPath, r.PrivateKeyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(r.AuthorizedKey), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}
