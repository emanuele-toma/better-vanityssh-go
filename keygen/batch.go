package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	voiCurve "github.com/oasisprotocol/curve25519-voi/curve"
	voiScalar "github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"golang.org/x/crypto/ssh"
)

// DefaultBatchSize is the default number of seeds read from crypto/rand per loop
// iteration. Larger batches amortize the syscall cost of rand.Reader across more
// keys. 64 is a reasonable default; tune with the tune-batch subcommand.
const DefaultBatchSize = 64

// defaultBatchSize aliases DefaultBatchSize for internal use.
const defaultBatchSize = DefaultBatchSize

// clampScalar applies RFC 8032 §5.1.5 clamping in-place on a 32-byte scalar.
// This must be applied to the first 32 bytes of SHA-512(seed) before using the
// bytes as an Ed25519 private scalar.
func clampScalar(b []byte) {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
}

// findKeysBatch is the optimized random-mode key generation path.
// It reads seeds in batches from crypto/rand, derives ED25519 key pairs via
// curve25519-voi's AVX2-accelerated ScalarBaseMult, and checks compressed
// public keys against the regex.
func findKeysBatch(ctx context.Context, opts Options, results chan<- Result) error {
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	seedBuf := make([]byte, batchSize*32)
	clamped := make([]byte, 32)

	wireKey := newWireKeyBuf()
	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)
	fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))

	var s voiScalar.Scalar
	var point voiCurve.EdwardsPoint
	var compressed voiCurve.CompressedEdwardsY

	var localCount int64
	const flushInterval = 1024

	for {
		if localCount >= flushInterval {
			globalCounter.Add(localCount)
			localCount = 0
			if ctx.Err() != nil {
				return nil
			}
		}

		// Read all seeds for this batch in one call, reducing syscall frequency by batchSize.
		if _, err := io.ReadFull(rand.Reader, seedBuf); err != nil {
			return fmt.Errorf("read random seeds: %w", err)
		}

		for i := range batchSize {
			localCount++
			seed := seedBuf[i*32 : (i+1)*32]

			digest := sha512.Sum512(seed)
			copy(clamped, digest[:32])
			clampScalar(clamped)
			if _, err := s.SetBits(clamped); err != nil {
				return fmt.Errorf("set scalar: %w", err)
			}
			point.MulBasepoint(voiCurve.ED25519_BASEPOINT_TABLE, &s)
			compressed.SetEdwardsPoint(&point)
			copy(wireKey[pubKeyOffset:], compressed[:])

			var matched bool
			if opts.Fingerprint {
				sum := sha256.Sum256(wireKey)
				base64.StdEncoding.Encode(fpBuf, sum[:])
				matched = opts.Regex.Match(fpBuf)
			} else {
				base64.StdEncoding.Encode(authKeyBuf[len(authKeyPrefix):], wireKey)
				matched = opts.Regex.Match(authKeyBuf)
			}

			if !matched {
				continue
			}

			// Match found — flush counters, then reconstruct the full private key.
			globalCounter.Add(localCount)
			localCount = 0
			matchCounter.Add(1)

			// ed25519.NewKeyFromSeed re-derives the same public key from the seed.
			// This is the slow path; it only runs on match.
			privKey := ed25519.NewKeyFromSeed(seed)
			publicKey, err := ssh.NewPublicKey(ed25519.PublicKey(privKey[32:]))
			if err != nil {
				return fmt.Errorf("convert public key: %w", err)
			}
			pemKey, err := ssh.MarshalPrivateKey(privKey, "")
			if err != nil {
				return fmt.Errorf("marshal private key: %w", err)
			}

			result := Result{
				PrivateKeyPEM: pem.EncodeToMemory(pemKey),
				AuthorizedKey: getAuthorizedKey(publicKey),
				Fingerprint:   getFingerprint(publicKey),
			}

			select {
			case results <- result:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
