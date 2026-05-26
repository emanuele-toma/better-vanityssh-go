// Tests that read or write the global counters (KeyCount, MatchCount,
// ResetCounters) must NOT be marked t.Parallel() — they share package-level
// atomic state. Adding t.Parallel() to such tests will introduce races.
package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// assertResultFields checks that a keygen.Result has all fields populated
// with correct prefixes. Does not re-validate stdlib crypto.
func assertResultFields(t *testing.T, r Result) {
	t.Helper()
	if len(r.PrivateKeyPEM) == 0 {
		t.Error("PrivateKeyPEM is empty")
	}
	if !strings.Contains(string(r.PrivateKeyPEM), "BEGIN OPENSSH PRIVATE KEY") {
		t.Error("PrivateKeyPEM missing PEM header")
	}
	if !strings.HasPrefix(r.AuthorizedKey, "ssh-ed25519 ") {
		t.Errorf("AuthorizedKey = %q, want prefix %q", r.AuthorizedKey, "ssh-ed25519 ")
	}
	if r.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
}

func TestNewWireKeyBuf(t *testing.T) {
	t.Parallel()

	buf := newWireKeyBuf()

	if len(buf) != wireKeyLen {
		t.Errorf("length = %d, want %d", len(buf), wireKeyLen)
	}
	if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 11 {
		t.Errorf("algo name length = [%d %d %d %d], want [0 0 0 11]",
			buf[0], buf[1], buf[2], buf[3])
	}
	if string(buf[4:15]) != "ssh-ed25519" {
		t.Errorf("algo name = %q, want %q", string(buf[4:15]), "ssh-ed25519")
	}
	if buf[15] != 0 || buf[16] != 0 || buf[17] != 0 || buf[18] != 32 {
		t.Errorf("key length = [%d %d %d %d], want [0 0 0 32]",
			buf[15], buf[16], buf[17], buf[18])
	}
	for i := pubKeyOffset; i < wireKeyLen; i++ {
		if buf[i] != 0 {
			t.Errorf("buf[%d] = %d, want 0 (public key slot should be zeroed)", i, buf[i])
			break
		}
	}
}

func TestNewWireKeyBuf_IndependentBuffers(t *testing.T) {
	t.Parallel()

	buf1 := newWireKeyBuf()
	buf2 := newWireKeyBuf()

	for i := range buf1 {
		buf1[i] = 0xFF
	}
	if buf2[3] != 11 {
		t.Fatal("buffers share memory")
	}
}

func TestHotPathSlowPathEquivalence(t *testing.T) {
	t.Parallel()

	for range 10 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("NewPublicKey: %v", err)
		}

		wireKey := newWireKeyBuf()
		copy(wireKey[pubKeyOffset:], pub)

		// Public key: hot path vs getAuthorizedKey.
		authKeyPrefix := []byte("ssh-ed25519 ")
		b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
		authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
		copy(authKeyBuf, authKeyPrefix)
		base64.StdEncoding.Encode(authKeyBuf[len(authKeyPrefix):], wireKey)
		if got, want := string(authKeyBuf), getAuthorizedKey(sshPub); got != want {
			t.Errorf("public key hot path %q != slow path %q", got, want)
		}

		// Fingerprint: hot path vs getFingerprint.
		sum := sha256.Sum256(wireKey)
		fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))
		base64.StdEncoding.Encode(fpBuf, sum[:])
		if got, want := string(fpBuf), getFingerprint(sshPub); got != want {
			t.Errorf("fingerprint hot path %q != slow path %q", got, want)
		}
	}
}

func TestResetCounters(t *testing.T) {
	// Not parallel: modifies global counter state.

	globalCounter.Add(100)
	matchCounter.Add(10)
	t.Cleanup(func() { ResetCounters() })

	ResetCounters()

	if got := KeyCount(); got != 0 {
		t.Errorf("KeyCount() = %d, want 0", got)
	}
	if got := MatchCount(); got != 0 {
		t.Errorf("MatchCount() = %d, want 0", got)
	}
}

func TestFindKeys_NilRegex(t *testing.T) {
	results := make(chan Result, 1)
	err := FindKeys(context.Background(), Options{Regex: nil}, results)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrNilRegex) {
		t.Errorf("error = %v, want %v", err, ErrNilRegex)
	}
	select {
	case r := <-results:
		t.Errorf("unexpected result: %+v", r)
	default:
	}
}

func TestFindKeys_Cancellation(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`.`)
	results := make(chan Result, 1)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re}, results)
	}()

	// Wait for at least one result to prove the worker was running.
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

func TestFindKeys_AlreadyCancelledContext(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`^IMPOSSIBLE$`)
	results := make(chan Result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re}, results)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return promptly")
	}
}

func TestFindKeys_MultipleMatches(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`ssh-ed25519`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := make(chan Result, 3)
	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re}, results)
	}()

	const want = 3
	seen := make(map[string]bool)
	for i := range want {
		select {
		case r := <-results:
			if r.AuthorizedKey == "" {
				t.Fatalf("match %d: empty AuthorizedKey", i+1)
			}
			seen[r.AuthorizedKey] = true
		case <-ctx.Done():
			t.Fatalf("timed out after %d matches", i)
		}
	}
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("FindKeys error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FindKeys did not return after cancel")
	}

	if len(seen) != want {
		t.Errorf("got %d distinct keys, want %d", len(seen), want)
	}
}

func TestFindKeys_BlockedSendCancellation(t *testing.T) {
	t.Parallel()

	results := make(chan Result) // unbuffered — send will block
	re := regexp.MustCompile(`ssh-ed25519`)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re}, results)
	}()

	select {
	case <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first result")
	}

	// Give the worker time to attempt the next blocked send.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("error on blocked-send cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return after cancel")
	}
}

func TestFindKeys_TrulySelectiveRegex(t *testing.T) {
	// Not parallel: depends on and resets global counter state.

	tests := []struct {
		name        string
		fingerprint bool
		checkField  func(Result) string
	}{
		{
			name:        "public key mode",
			fingerprint: false,
			checkField:  func(r Result) string { return r.AuthorizedKey },
		},
		{
			name:        "fingerprint mode",
			fingerprint: true,
			checkField:  func(r Result) string { return r.Fingerprint },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ResetCounters()
			t.Cleanup(func() { ResetCounters() })

			re := regexp.MustCompile(`ZZ`)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			results := make(chan Result, 1)
			errCh := make(chan error, 1)
			go func() {
				errCh <- FindKeys(ctx, Options{Regex: re, Fingerprint: tt.fingerprint}, results)
			}()

			select {
			case r := <-results:
				cancel()
				if err := <-errCh; err != nil {
					t.Fatalf("FindKeys error: %v", err)
				}
				if !re.MatchString(tt.checkField(r)) {
					t.Errorf("result does not match regex: %q", tt.checkField(r))
				}
				assertResultFields(t, r)

				if matches := MatchCount(); matches < 1 {
					t.Errorf("MatchCount() = %d, want >= 1", matches)
				}
				if keys, matches := KeyCount(), MatchCount(); keys <= matches {
					t.Errorf("KeyCount() = %d <= MatchCount() = %d; regex did not reject any keys", keys, matches)
				}
			case <-ctx.Done():
				t.Fatal("timed out")
			}
		})
	}
}

func TestFindKeys_FingerprintModeRejectsPubKeyPattern(t *testing.T) {
	// Not parallel: verifies keys were generated via global counter.

	ResetCounters()
	t.Cleanup(func() { ResetCounters() })

	// This regex matches every authorized key but can never match a fingerprint.
	re := regexp.MustCompile(`^ssh-ed25519 `)
	ctx, cancel := context.WithCancel(context.Background())

	results := make(chan Result, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- FindKeys(ctx, Options{Regex: re, Fingerprint: true}, results)
	}()

	deadline := time.After(10 * time.Second)
	for KeyCount() < 1024 {
		select {
		case r := <-results:
			t.Fatalf("fingerprint mode matched pubkey-only pattern: %+v", r)
		case <-deadline:
			t.Fatalf("KeyCount() = %d, want >= 1024", KeyCount())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("FindKeys error: %v", err)
	}
}

func TestFindKeys_ConcurrentWorkers(t *testing.T) {
	t.Parallel()

	const numWorkers = 8
	const matchesWanted = 4

	re := regexp.MustCompile(`ssh-ed25519`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := make(chan Result, matchesWanted)
	errCh := make(chan error, numWorkers)
	for range numWorkers {
		go func() {
			errCh <- FindKeys(ctx, Options{Regex: re}, results)
		}()
	}

	seen := make(map[string]bool)
	for range matchesWanted {
		select {
		case r := <-results:
			seen[r.AuthorizedKey] = true
			assertResultFields(t, r)
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

// --- Batch compression correctness ---

// TestBatchCompressionMatchesStdlib verifies that batchCompressPoints produces
// identical 32-byte public keys to ed25519.NewKeyFromSeed for a set of known seeds.
// This is the critical correctness gate before the batch path can be trusted.
func TestBatchCompressionMatchesStdlib(t *testing.T) {
	t.Parallel()

	const n = defaultBatchSize
	seeds := make([][]byte, n)
	wantPubKeys := make([][32]byte, n)
	for i := range n {
		seed := make([]byte, 32)
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		seeds[i] = seed
		privKey := ed25519.NewKeyFromSeed(seed)
		copy(wantPubKeys[i][:], privKey[32:])
	}

	bs := newBatchState()
	// Fill seedBuf with our test seeds.
	for i, seed := range seeds {
		copy(bs.seedBuf[i*32:(i+1)*32], seed)
	}

	// Derive scalars and compute points (mirrors findKeysBatch internals).
	for i := range n {
		digest := sha512.Sum512(seeds[i])
		if _, err := bs.scalars[i].SetBytesWithClamping(digest[:32]); err != nil {
			t.Fatalf("seed %d: SetBytesWithClamping: %v", i, err)
		}
		bs.points[i].ScalarBaseMult(bs.scalars[i])
	}

	batchCompressPoints(bs)

	for i := range n {
		if bs.pubKeys[i] != wantPubKeys[i] {
			t.Errorf("key[%d]: batch got %x, stdlib got %x", i, bs.pubKeys[i], wantPubKeys[i])
		}
	}
}

// --- Phase 1 benchmarks: isolate each hot-loop stage ---

// BenchmarkRandBytes measures the cost of reading 32 bytes from crypto/rand.
// Used to quantify getrandom() syscall overhead per key.
func BenchmarkRandBytes(b *testing.B) {
	buf := make([]byte, 32)
	b.ResetTimer()
	for range b.N {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRandBytesBatched measures amortized rand cost when reading 1024 seeds at once.
func BenchmarkRandBytesBatched(b *testing.B) {
	const batchSize = 1024
	buf := make([]byte, batchSize*32)
	b.ResetTimer()
	for i := range b.N {
		if i%batchSize == 0 {
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				b.Fatal(err)
			}
		}
		_ = buf[(i%batchSize)*32 : (i%batchSize+1)*32]
	}
}

// BenchmarkSHA512 measures SHA-512 over a 32-byte seed (the key derivation step).
func BenchmarkSHA512(b *testing.B) {
	seed := make([]byte, 32)
	b.ResetTimer()
	for range b.N {
		h := sha512.New()
		h.Write(seed)
		_ = h.Sum(nil)
	}
}

// BenchmarkNewKeyFromSeed measures the deterministic key path (no syscall): SHA-512 + ScalarBaseMult + compress.
func BenchmarkNewKeyFromSeed(b *testing.B) {
	seed := make([]byte, 32)
	b.ResetTimer()
	for range b.N {
		_ = ed25519.NewKeyFromSeed(seed)
	}
}

// BenchmarkGenerateKey measures the full stdlib key generation path including crypto/rand.
func BenchmarkGenerateKey(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		if _, _, err := ed25519.GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHotLoop measures the complete hot loop: GenerateKey + wire encode + base64 + regex.
// This is the end-to-end throughput benchmark. Use its CPU profile to identify the bottleneck.
func BenchmarkHotLoop(b *testing.B) {
	re := regexp.MustCompile(`.`)
	wireKey := newWireKeyBuf()
	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)
	b.ResetTimer()
	for range b.N {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		copy(wireKey[pubKeyOffset:], pub)
		base64.StdEncoding.Encode(authKeyBuf[len(authKeyPrefix):], wireKey)
		_ = re.Match(authKeyBuf)
	}
}

// BenchmarkBatchCompress measures the amortized per-key cost of batchCompressPoints.
// Compare to BenchmarkPointCompress to see the Montgomery batch inversion speedup.
func BenchmarkBatchCompress(b *testing.B) {
	bs := newBatchState()
	// Pre-compute all points using fixed scalars (isolates compression cost).
	for i := range defaultBatchSize {
		seed := make([]byte, 32)
		seed[0] = byte(i)
		digest := sha512.Sum512(seed)
		if _, err := bs.scalars[i].SetBytesWithClamping(digest[:32]); err != nil {
			b.Fatal(err)
		}
		bs.points[i].ScalarBaseMult(bs.scalars[i])
	}
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		batchCompressPoints(bs)
	}
	b.ReportMetric(float64(defaultBatchSize), "keys/op")
}

// BenchmarkHotLoopBatch measures the new batch pipeline: defaultBatchSize keys generated,
// batch-compressed, and regex-matched per outer loop iteration.
// Compare to BenchmarkHotLoop (single-key path) to see the overall throughput gain.
func BenchmarkHotLoopBatch(b *testing.B) {
	re := regexp.MustCompile(`.`)
	wireKey := newWireKeyBuf()
	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)

	bs := newBatchState()
	b.ResetTimer()
	b.ReportAllocs()
	// Each b.N iteration processes a full batch of defaultBatchSize keys.
	for range b.N {
		if _, err := io.ReadFull(rand.Reader, bs.seedBuf); err != nil {
			b.Fatal(err)
		}
		for i := range defaultBatchSize {
			seed := bs.seedBuf[i*32 : (i+1)*32]
			digest := sha512.Sum512(seed)
			if _, err := bs.scalars[i].SetBytesWithClamping(digest[:32]); err != nil {
				b.Fatal(err)
			}
			bs.points[i].ScalarBaseMult(bs.scalars[i])
		}
		batchCompressPoints(bs)
		for i := range defaultBatchSize {
			copy(wireKey[pubKeyOffset:], bs.pubKeys[i][:])
			base64.StdEncoding.Encode(authKeyBuf[len(authKeyPrefix):], wireKey)
			_ = re.Match(authKeyBuf)
		}
	}
	b.ReportMetric(float64(defaultBatchSize), "keys/op")
}

// BenchmarkHotLoopFingerprint measures the fingerprint-mode hot loop variant.
func BenchmarkHotLoopFingerprint(b *testing.B) {
	re := regexp.MustCompile(`.`)
	wireKey := newWireKeyBuf()
	fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))
	b.ResetTimer()
	for range b.N {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		copy(wireKey[pubKeyOffset:], pub)
		sum := sha256.Sum256(wireKey)
		base64.StdEncoding.Encode(fpBuf, sum[:])
		_ = re.Match(fpBuf)
	}
}
