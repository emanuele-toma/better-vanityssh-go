package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	voiCurve "github.com/oasisprotocol/curve25519-voi/curve"
	voiScalar "github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ssh"
)

// deterministicBatchSize is the number of keys generated per atomic index
// reservation. Must be even so batches always start on a 64-byte ChaCha20
// block boundary (each block holds two 32-byte ED25519 seeds).
const deterministicBatchSize = 1024

// ErrIndexOverflow is returned when the deterministic key index would exceed
// ChaCha20's maximum capacity of 2^33 keys (~8.6 billion).
var ErrIndexOverflow = errors.New("deterministic key index overflow: exceeded 2^33 keys")

// DeriveSeed derives a 32-byte ChaCha20 key from a passphrase using Argon2id.
// The same passphrase always produces the same seed, enabling reproducible
// key generation and checkpoint resume.
func DeriveSeed(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), []byte("vanityssh-go"), 1, 64*1024, 4, 32)
}

// deterministicFindKeys is the deterministic variant of FindKeys.
// It consumes a ChaCha20 keystream seeded from opts.DerivedSeed, generating
// ED25519 keys in batches indexed by the shared deterministicIndex counter.
func deterministicFindKeys(ctx context.Context, opts Options, results chan<- Result) error {
	zeroNonce := make([]byte, chacha20.NonceSize)

	wireKey := newWireKeyBuf()
	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)
	fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))

	// keystream holds one batch's worth of ChaCha20 output (each 32 bytes = one ED25519 seed).
	keystream := make([]byte, deterministicBatchSize*32)
	zeros := make([]byte, deterministicBatchSize*32)

	for {
		if ctx.Err() != nil {
			return nil
		}

		end := deterministicIndex.Add(deterministicBatchSize)
		start := end - deterministicBatchSize

		// ChaCha20 with 32-bit block counter holds 2^32 * 64 bytes = 2^38 bytes total,
		// enough for 2^33 32-byte seeds. Guard against exceeding that.
		if uint64(start) >= (1 << 33) {
			return ErrIndexOverflow
		}

		// Create a fresh cipher per batch and seek to block start/2.
		// Since start is always a multiple of deterministicBatchSize (even),
		// start/2 is always an integer and we always begin at a block boundary.
		cipher, err := chacha20.NewUnauthenticatedCipher(opts.DerivedSeed, zeroNonce)
		if err != nil {
			return fmt.Errorf("create chacha20 cipher: %w", err)
		}
		cipher.SetCounter(uint32(start / 2))
		cipher.XORKeyStream(keystream, zeros)

		var (
			s          voiScalar.Scalar
			point      voiCurve.EdwardsPoint
			compressed voiCurve.CompressedEdwardsY
			clamped    = make([]byte, 32)
		)

		var localCount int64
		for i := range deterministicBatchSize {
			localCount++

			seed := keystream[i*32 : (i+1)*32]
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

			// Match found — flush counter, build result (slow path).
			globalCounter.Add(localCount)
			localCount = 0
			matchCounter.Add(1)

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

		globalCounter.Add(localCount)
	}
}
