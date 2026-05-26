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

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/ssh"
)

// defaultBatchSize is the number of keys generated and compressed together per iteration.
// At N=16, Montgomery's trick amortizes 1 field inversion across 16 points, reducing
// the per-key compression cost from ~5750 ns to ~400 ns (~14x speedup on that step).
const defaultBatchSize = 16

// batchState holds pre-allocated working buffers for one batch of key generation.
// Declared before its consuming functions per CS-6.
type batchState struct {
	seedBuf []byte                  // defaultBatchSize * 32 raw random bytes
	scalars []*edwards25519.Scalar  // one per key in the batch
	points  []*edwards25519.Point   // uncompressed points after ScalarBaseMult
	xs, ys  []field.Element         // X and Y affine coordinates (copied from ExtendedCoordinates)
	zs      []field.Element         // Z projective coordinates
	prefix  []field.Element         // running prefix products for Montgomery trick
	zInvs   []field.Element         // per-point Z^{-1} after batch inversion
	pubKeys [][32]byte              // compressed 32-byte public key output
}

func newBatchState() *batchState {
	bs := &batchState{
		seedBuf: make([]byte, defaultBatchSize*32),
		scalars: make([]*edwards25519.Scalar, defaultBatchSize),
		points:  make([]*edwards25519.Point, defaultBatchSize),
		xs:      make([]field.Element, defaultBatchSize),
		ys:      make([]field.Element, defaultBatchSize),
		zs:      make([]field.Element, defaultBatchSize),
		prefix:  make([]field.Element, defaultBatchSize),
		zInvs:   make([]field.Element, defaultBatchSize),
		pubKeys: make([][32]byte, defaultBatchSize),
	}
	for i := range defaultBatchSize {
		bs.scalars[i] = edwards25519.NewScalar()
		bs.points[i] = new(edwards25519.Point)
	}
	return bs
}

// batchCompressPoints compresses defaultBatchSize points into bs.pubKeys using
// Montgomery's batch inversion trick.
//
// Instead of N independent field inversions (each ~5750 ns), the trick uses:
//   - N-1 prefix multiplications to build a running product of all Z coordinates
//   - 1 inversion of the total product
//   - N-1 backward multiplications to recover per-point Z^{-1}
//
// Total: 3(N-1) multiplications + 1 inversion, vs N inversions naively.
func batchCompressPoints(bs *batchState) {
	// Step 1: extract X, Y, Z from each uncompressed point.
	for i, p := range bs.points {
		X, Y, Z, _ := p.ExtendedCoordinates()
		bs.xs[i].Set(X)
		bs.ys[i].Set(Y)
		bs.zs[i].Set(Z)
	}

	// Step 2: build prefix products prefix[i] = Z_0 * Z_1 * ... * Z_i.
	bs.prefix[0].Set(&bs.zs[0])
	for i := 1; i < defaultBatchSize; i++ {
		bs.prefix[i].Multiply(&bs.prefix[i-1], &bs.zs[i])
	}

	// Step 3: invert the total product (prefix[N-1] = Z_0 * ... * Z_{N-1}).
	var allInv field.Element
	allInv.Invert(&bs.prefix[defaultBatchSize-1])

	// Step 4: recover per-point Z^{-1} in a backwards pass.
	// zInvs[i] = allInv * prefix[i-1], then allInv = allInv * Z_i.
	for i := defaultBatchSize - 1; i > 0; i-- {
		bs.zInvs[i].Multiply(&allInv, &bs.prefix[i-1])
		allInv.Multiply(&allInv, &bs.zs[i])
	}
	bs.zInvs[0].Set(&allInv)

	// Step 5: compress each point — encode y = Y/Z, set high bit from sign of x = X/Z.
	var x, y field.Element
	for i := range defaultBatchSize {
		x.Multiply(&bs.xs[i], &bs.zInvs[i])
		y.Multiply(&bs.ys[i], &bs.zInvs[i])
		copy(bs.pubKeys[i][:], y.Bytes())
		bs.pubKeys[i][31] |= byte(x.IsNegative()) << 7
	}
}

// findKeysBatch is the optimized random-mode key generation path.
// It generates keys in batches of defaultBatchSize, using batch point compression
// to amortize the expensive field inversion across all points in a batch.
func findKeysBatch(ctx context.Context, opts Options, results chan<- Result) error {
	bs := newBatchState()

	wireKey := newWireKeyBuf()

	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)

	fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))

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

		// Read all seeds for this batch in one call, reducing syscall frequency by defaultBatchSize.
		if _, err := io.ReadFull(rand.Reader, bs.seedBuf); err != nil {
			return fmt.Errorf("read random seeds: %w", err)
		}

		// Derive ed25519 scalars and compute uncompressed Edwards points.
		for i := range defaultBatchSize {
			seed := bs.seedBuf[i*32 : (i+1)*32]
			digest := sha512.Sum512(seed)
			if _, err := bs.scalars[i].SetBytesWithClamping(digest[:32]); err != nil {
				return fmt.Errorf("set scalar: %w", err)
			}
			bs.points[i].ScalarBaseMult(bs.scalars[i])
		}

		// Compress all defaultBatchSize points with a single field inversion.
		batchCompressPoints(bs)

		// Check each compressed key against the regex.
		for i := range defaultBatchSize {
			localCount++
			copy(wireKey[pubKeyOffset:], bs.pubKeys[i][:])

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
			seed := bs.seedBuf[i*32 : (i+1)*32]
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
