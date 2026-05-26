// Tests that read or write deterministicIndex must NOT be marked t.Parallel() —
// they share the same package-level atomic state as globalCounter and matchCounter.
package keygen

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	voiCurve "github.com/oasisprotocol/curve25519-voi/curve"
	voiScalar "github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"golang.org/x/crypto/chacha20"
)

func TestDeriveSeed_Determinism(t *testing.T) {
	t.Parallel()

	a := DeriveSeed("hello")
	b := DeriveSeed("hello")
	if !bytes.Equal(a, b) {
		t.Error("same passphrase produced different seeds")
	}

	c := DeriveSeed("world")
	if bytes.Equal(a, c) {
		t.Error("different passphrases produced identical seeds")
	}
}

func TestDeriveSeed_Length(t *testing.T) {
	t.Parallel()

	seed := DeriveSeed("test")
	if len(seed) != 32 {
		t.Errorf("len(seed) = %d, want 32", len(seed))
	}
}

func TestDetermFindKeys_NilRegex(t *testing.T) {
	seed := DeriveSeed("test")
	results := make(chan Result, 1)
	err := FindKeys(context.Background(), Options{Regex: nil, DerivedSeed: seed}, results)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrNilRegex) {
		t.Errorf("error = %v, want %v", err, ErrNilRegex)
	}
}

func TestDetermFindKeys_Cancellation(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	ResetCounters()
	t.Cleanup(func() { ResetCounters() })

	seed := DeriveSeed("cancel-test")
	re := regexp.MustCompile(`.`)
	results := make(chan Result, 1)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re, DerivedSeed: seed}, results)
	}()

	select {
	case <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("no result before cancellation")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("FindKeys error on cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FindKeys did not return after cancel")
	}
}

func TestDetermFindKeys_Determinism(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	// Run twice with the same passphrase and collect the first match each time.
	// The key at any given index must be identical across runs.

	collect := func() Result {
		ResetCounters()
		t.Cleanup(func() { ResetCounters() })

		seed := DeriveSeed("determ-test")
		re := regexp.MustCompile(`ssh-ed25519`)
		results := make(chan Result, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- FindKeys(ctx, Options{Regex: re, DerivedSeed: seed}, results)
		}()

		select {
		case r := <-results:
			cancel()
			if err := <-errCh; err != nil {
				t.Fatalf("FindKeys error: %v", err)
			}
			return r
		case <-ctx.Done():
			t.Fatal("timed out")
			return Result{}
		}
	}

	first := collect()
	second := collect()

	if first.AuthorizedKey != second.AuthorizedKey {
		t.Errorf("determinism failed:\n  run 1: %q\n  run 2: %q", first.AuthorizedKey, second.AuthorizedKey)
	}
}

func TestDetermFindKeys_DifferentPassphrases(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	ResetCounters()
	t.Cleanup(func() { ResetCounters() })

	collect := func(passphrase string) string {
		ResetCounters()
		seed := DeriveSeed(passphrase)
		re := regexp.MustCompile(`ssh-ed25519`)
		results := make(chan Result, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			errCh <- FindKeys(ctx, Options{Regex: re, DerivedSeed: seed}, results)
		}()
		select {
		case r := <-results:
			cancel()
			if err := <-errCh; err != nil {
				t.Fatalf("FindKeys error: %v", err)
			}
			return r.AuthorizedKey
		case <-ctx.Done():
			t.Fatal("timed out")
			return ""
		}
	}

	a := collect("passphrase-A")
	b := collect("passphrase-B")
	if a == b {
		t.Errorf("different passphrases produced the same first key: %q", a)
	}
}

func TestDetermFindKeys_MatchFingerprint(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	ResetCounters()
	t.Cleanup(func() { ResetCounters() })

	seed := DeriveSeed("fp-test")
	re := regexp.MustCompile(`[A-Za-z0-9+/]`)
	results := make(chan Result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re, Fingerprint: true, DerivedSeed: seed}, results)
	}()

	select {
	case r := <-results:
		cancel()
		if err := <-errCh; err != nil {
			t.Fatalf("FindKeys error: %v", err)
		}
		if r.Fingerprint == "" {
			t.Error("Fingerprint is empty")
		}
		if !re.MatchString(r.Fingerprint) {
			t.Errorf("Fingerprint %q does not match regex", r.Fingerprint)
		}
	case <-ctx.Done():
		t.Fatal("timed out")
	}
}

func TestDetermFindKeys_IndexMonotonicity(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	// Verify that concurrent workers never allocate overlapping batch ranges.
	ResetCounters()
	t.Cleanup(func() { ResetCounters() })

	const numWorkers = 4
	const matchesWanted = numWorkers * 2

	seed := DeriveSeed("monotonicity-test")
	re := regexp.MustCompile(`ssh-ed25519`)
	results := make(chan Result, matchesWanted)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, numWorkers)
	for range numWorkers {
		go func() {
			errCh <- FindKeys(ctx, Options{Regex: re, DerivedSeed: seed}, results)
		}()
	}

	seen := make(map[string]bool)
	var mu sync.Mutex
	for range matchesWanted {
		select {
		case r := <-results:
			mu.Lock()
			if seen[r.AuthorizedKey] {
				t.Errorf("duplicate result: %q", r.AuthorizedKey)
			}
			seen[r.AuthorizedKey] = true
			mu.Unlock()
		case <-ctx.Done():
			t.Fatalf("timed out after %d/%d results", len(seen), matchesWanted)
		}
	}
	cancel()

	for range numWorkers {
		if err := <-errCh; err != nil {
			t.Errorf("FindKeys error: %v", err)
		}
	}

	if len(seen) != matchesWanted {
		t.Errorf("got %d distinct keys, want %d", len(seen), matchesWanted)
	}
}

// BenchmarkDetermHotLoop measures the hot-path cost of the deterministic mode:
// ChaCha20 keystream + voi ScalarBaseMult + voi compress.
// Compare to BenchmarkNewKeyFromSeed (stdlib) to quantify the speedup.
func BenchmarkDetermHotLoop(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, chacha20.NonceSize)
	ks := make([]byte, defaultBatchSize*32)
	zeros := make([]byte, defaultBatchSize*32)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		b.Fatal(err)
	}
	cipher.XORKeyStream(ks, zeros)

	clamped := make([]byte, 32)
	var s voiScalar.Scalar
	var point voiCurve.EdwardsPoint
	var compressed voiCurve.CompressedEdwardsY

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		for i := range defaultBatchSize {
			seed := ks[i*32 : (i+1)*32]
			digest := sha512.Sum512(seed)
			copy(clamped, digest[:32])
			clampScalar(clamped)
			if _, err := s.SetBits(clamped); err != nil {
				b.Fatal(err)
			}
			point.MulBasepoint(voiCurve.ED25519_BASEPOINT_TABLE, &s)
			compressed.SetEdwardsPoint(&point)
		}
	}
	b.ReportMetric(float64(defaultBatchSize), "keys/op")
}

func TestSetDetermIndex_AlignsTooBatch(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	t.Cleanup(func() { ResetCounters() })

	tests := []struct {
		input int64
		want  int64
	}{
		{0, 0},
		{1023, 0},
		{1024, 1024},
		{1025, 1024},
		{2047, 1024},
		{2048, 2048},
		{5000, 4096},
	}
	for _, tt := range tests {
		SetDetermIndex(tt.input)
		if got := DetermIndex(); got != tt.want {
			t.Errorf("SetDetermIndex(%d): DetermIndex() = %d, want %d", tt.input, got, tt.want)
		}
	}
}
