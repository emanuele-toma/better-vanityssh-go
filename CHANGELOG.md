# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-05-26

### Added

- Add `-b` shorthand for `--batch-size`, `-C` shorthand for `--checkpoint`, and `-m` shorthand for `estimate --max-length`

## [0.2.1] - 2026-05-26

### Changed

- Switch hot-path ScalarBaseMult from `filippo.io/edwards25519` to `oasisprotocol/curve25519-voi`, which uses AVX2-parallel field arithmetic on amd64. This gives ~70% faster scalar multiplication (8,047 ns vs 13,687 ns) and ~21% higher end-to-end key generation throughput (11.4 µs/key vs 14.4 µs/key). Deterministic mode (`--passphrase`) improves ~38% compared to the previous `crypto/ed25519.NewKeyFromSeed` baseline
- Remove the Montgomery batch inversion trick for point compression (compression is now dominated by ScalarBaseMult; the trick is no longer the bottleneck)
- Change default `--batch-size` from 16 to 64 (now controls seeds read from `crypto/rand` per loop iteration, not compression batch size)
- Update `--batch-size` and `tune-batch` documentation to reflect new batch semantics (rand read amortization instead of Montgomery trick)

### Added

- Add `tune-batch` subcommand that sweeps batch sizes and reports the optimal for the current CPU
- Add `--batch-size` flag to configure seeds read from `crypto/rand` per loop iteration; defaults to 64
- Export `keygen.DefaultBatchSize` for use in tooling

### Fixed

- Fix `make build` to produce a `vanityssh-go` binary (was using `go build ./...` which discards main package output)
- Correct README throughput gain from ~22% to ~29% (22% is the ns/key reduction; the throughput gain is +29%)
- Align README compression benchmark numbers with code comments (~5,750 ns → ~400 ns, ~14×)
- Remove inaccurate text from README usage block
- Correct README safety section: batch path uses `filippo.io/edwards25519/field` directly for point compression, not solely `crypto/ed25519`
- Add note that `go install` produces a binary named `better-vanityssh-go`, not `vanityssh`

## [0.2.0] - 2026-05-26

### Added

- Add `estimate` subcommand that benchmarks key generation speed and prints a
  probability matrix with estimated times to find a vanity key at 50%, 75%,
  and 90% confidence, across three match strategies: prefix/suffix (fixed
  position), contains in public key, and contains in SHA256 fingerprint.
  Accepts `--jobs` (thread count), `--duration` (benchmark length), and
  `--max-length` (rows to display) flags.
- Add `--output`/`-o` flag to specify a directory for saved key files; in
  continuous mode each match is written as `id_ed25519_N` / `id_ed25519_N.pub`,
  in single-match mode keys are written as `id_ed25519` / `id_ed25519.pub`
- Add `--passphrase`/`-p` flag for deterministic key generation: derives a
  ChaCha20 keystream via Argon2id so the same passphrase always produces the
  same key at the same index, enabling reproducible searches
- Add `--checkpoint` flag (requires `--passphrase`) to save and resume
  progress from a JSON file; state is saved every 5 minutes and on exit
- Show key index in status bar when running in deterministic mode

### Added

- Add GitHub Actions release pipeline (`.github/workflows/release.yml`) that
  triggers on `v*` tags, sets up Go, and runs GoReleaser to publish binaries
  to GitHub Releases

### Changed

- Update Go toolchain to 1.25.0 and refresh `golang.org/x/*` dependencies
- Add `-trimpath` to GoReleaser build flags for reproducible builds
- Improve random-mode key generation throughput by ~22% via Montgomery batch
  point compression: 16 Ed25519 keys are generated and their curve points
  compressed together using a single field inversion (Montgomery's trick),
  reducing per-key compression cost from ~5750 ns to ~556 ns

## [0.1.1] - 2026-02-23

### Fixed

- Fix duplicate match output in TTY single-match mode
- Fix match counter showing inflated numbers with concurrent workers

## [0.1.0] - 2026-02-16

### Added

- Cobra CLI rewrite with `--fingerprint`, `--continuous`, `--jobs` flags
- Context-based goroutine lifecycle with `errgroup` for clean shutdown
- `keygen.Result` type — `FindKeys` is now a pure worker sending results via channel
- Error handling for all key generation operations (no silent suppression)
- Pinned terminal status bar with scroll region for TTY output
- SHA256 fingerprint display on match
- Homebrew tap via GoReleaser (`brew install emanueletoma/tap/vanityssh`)
- GoReleaser-based release automation (darwin/linux/windows, amd64/arm64)
- CI pipeline with reusable workflows (go-ci, pr-conventions, lint)
- Pre-commit hooks (branch naming, commit messages, go-vet, go-build, go-test)
- Dependabot for GitHub Actions and Go module updates
- Makefile with build, test, vet targets
- Export `ErrNilRegex` sentinel error for programmatic nil-regex detection
  via `errors.Is`
- CHANGELOG.md

### Fixed

- Fix data race on `isTTY` flag by converting to `atomic.Bool`
- Fix `Reset()` writing to stderr without holding the display mutex
- Fix `UpdateStatusBar` writing ANSI escapes in non-TTY environments
- Fix `FormatCount` for negative numbers and `math.MinInt64` overflow
- Clamp terminal height to minimum 3 to prevent invalid ANSI sequences
- Reject negative `--jobs` values that caused the program to hang
- Return `ErrNilRegex` from `FindKeys` instead of panicking on nil regex
- Fix `OverrideTTY` data race on `termHeight` (CC-3: missing mutex)
- Fix `--continuous` in TTY mode silently discarding matched keys

### Changed

- Default branch renamed from `master` to `main`
- Deferred PEM encoding until match found (performance optimization)
- Hot loop uses pre-allocated buffers and batched atomic counters
- Replaced `ioutil.WriteFile` with `os.WriteFile`

### Removed

- Seven external dependencies ejected during Cobra rewrite
- Old CI workflows (build-go.yml, create-release-tag.yaml, release-artefacts.yaml)
- `build-cmds.txt` (replaced by Makefile)

### Tests

- Add `cmd` test suite: CLI validation, `handleResult` file writing and
  permissions, TTY/non-TTY output paths, write-error propagation, flag
  wiring, end-to-end pipeline
- Add `display` TTY-mode tests, concurrency stress tests, and edge cases
- Add `keygen` tests: cancellation, blocked-send, selective regex, concurrent
  workers, hot-path/slow-path equivalence, fingerprint-mode isolation
