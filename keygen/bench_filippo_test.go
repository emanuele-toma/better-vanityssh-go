// Benchmarks that isolate ScalarBaseMult and PointCompress via filippo.io/edwards25519.
// These benchmarks require the filippo dependency and exist solely to profile
// the hot-loop breakdown for the Phase 1 decision gate.
package keygen

import (
	"crypto/sha512"
	"testing"

	"filippo.io/edwards25519"
)

func fixedScalar(b *testing.B) *edwards25519.Scalar {
	b.Helper()
	seed := make([]byte, 32)
	h := sha512.New()
	h.Write(seed)
	digest := h.Sum(nil)
	s := edwards25519.NewScalar()
	if _, err := s.SetBytesWithClamping(digest[:32]); err != nil {
		b.Fatalf("SetBytesWithClamping: %v", err)
	}
	return s
}

// BenchmarkScalarBaseMult measures the Edwards scalar multiplication cost in isolation.
func BenchmarkScalarBaseMult(b *testing.B) {
	s := fixedScalar(b)
	b.ResetTimer()
	for range b.N {
		_ = new(edwards25519.Point).ScalarBaseMult(s)
	}
}

// BenchmarkPointCompress measures the cost of compressing a single Edwards point to bytes.
// This is the operation that Montgomery batch inversion would amortize.
func BenchmarkPointCompress(b *testing.B) {
	s := fixedScalar(b)
	p := new(edwards25519.Point).ScalarBaseMult(s)
	b.ResetTimer()
	for range b.N {
		_ = p.Bytes()
	}
}
