# better-vanityssh-go

Generate ED25519 SSH key pairs at high speed and match the resulting public
keys (or SHA256 fingerprints) against a regex pattern.

## Performance improvements over the original

This fork adds several performance and usability improvements on top of the
[original vanityssh-go](https://github.com/danielewood/vanityssh-go).

### AVX2-accelerated scalar multiplication (~68% throughput gain)

Profiling showed that Edwards scalar base multiplication (`ScalarBaseMult`) is
93% of key generation time. The hot path now uses
[`oasisprotocol/curve25519-voi`](https://github.com/oasisprotocol/curve25519-voi),
which automatically dispatches to an AVX2-parallel field arithmetic
implementation on amd64. The AVX2 path packs four field multiplications into a
single SIMD pass, cutting `ScalarBaseMult` from **13,687 ns to 8,047 ns** — a
70% speedup on that step alone.

Measured on AMD Ryzen 7 3800X (full hot loop including rand + SHA-512 +
ScalarBaseMult + compress + base64 + regex):

| Approach | ns/key | keys/sec/core |
|---|---|---|
| stdlib `crypto/ed25519`, single key | ~19,200 | ~52,000 |
| v0.2.0: filippo + Montgomery batch (16 keys) | ~14,400 | ~69,000 |
| **Current: curve25519-voi AVX2** | **~11,400** | **~87,600** |

Deterministic mode (`--passphrase`) receives the same improvement: **~11,000 ns/key**,
down from ~17,700 ns/key in the original `crypto/ed25519.NewKeyFromSeed` path.

### `make build` output

`make build` produces a `vanityssh-go` binary in the current directory (the
project root). The GoReleaser binary name used in releases is `vanityssh`.

## Is it safe to use?

Yes. Key generation uses `crypto/rand` for entropy and
`oasisprotocol/curve25519-voi` for curve arithmetic. On match, the private key
is reconstructed via the Go standard library's `crypto/ed25519.NewKeyFromSeed`
and serialized with `golang.org/x/crypto/ssh.MarshalPrivateKey` in the current
OpenSSH format. A correctness test verifies that the voi hot path produces
identical public keys to the stdlib reference for all inputs.

## Installation

### From releases

Download a prebuilt binary from the
[releases page](https://github.com/emanueletoma/better-vanityssh-go/releases).

### From source

```bash
go install github.com/emanueletoma/better-vanityssh-go@latest
```

> **Note:** `go install` names the binary `better-vanityssh-go`. Rename it
> to `vanityssh` to match the examples below.

### Build locally

```bash
git clone https://github.com/emanueletoma/better-vanityssh-go
cd better-vanityssh-go
make build   # produces ./vanityssh-go
```

## Usage

```text
vanityssh generates ED25519 SSH key pairs at high speed and matches
the resulting public keys (or SHA256 fingerprints) against a regex pattern.

On first match, the key pair is written to id_ed25519 and id_ed25519.pub
in the current directory. Use --continuous to keep finding keys.

When piping, only the private key is written to stdout.

Usage:
  vanityssh <regex> [flags]
  vanityssh [command]

Available Commands:
  estimate    Show probability matrix for finding a vanity key
  tune-batch  Find the optimal batch size for your CPU

Flags:
  -b, --batch-size int      seeds read from crypto/rand per loop iteration (default: 64; use 'tune-batch' to find optimal)
  -C, --checkpoint string   checkpoint file path for saving/resuming progress (requires --passphrase)
  -c, --continuous          keep finding keys after a match
  -f, --fingerprint         match against SHA256 fingerprint instead of public key
  -h, --help                help for vanityssh
  -j, --jobs int            number of parallel workers (default: number of CPUs)
  -o, --output string       directory to save key files (default: current directory)
  -p, --passphrase string   derive deterministic seed via Argon2id (enables reproducible key generation)
  -v, --version             version for vanityssh
```

### `estimate` subcommand

Before committing to a long search, use `estimate` to benchmark your CPU and
see how long a given pattern is likely to take:

```text
Usage:
  vanityssh estimate [flags]

Flags:
  -d, --duration duration   benchmark duration (default 3s)
  -h, --help                help for estimate
  -j, --jobs int            number of parallel workers (default: number of CPUs)
  -m, --max-length int      maximum string length to show in the matrix (1-16) (default 8)
```

Three match strategies are analyzed:

| Strategy | Description | P(one key) |
|---|---|---|
| Prefix / Suffix | anchored regex, e.g. `^abc` or `abc$` | 1 / 64^n |
| Contains in key | unanchored regex, anywhere in ~43 random chars | 1 − (1 − 1/64^n)^(43−n+1) |
| Contains in fingerprint | unanchored with `--fingerprint`, all 43 chars random | 1 − (1 − 1/64^n)^(43−n+1) |

### `tune-batch` subcommand

The batch size controls how many seeds are read from `crypto/rand` per loop
iteration. Larger batches amortize the syscall cost, but eventually cause cache
pressure. The optimal value is CPU-specific — run `tune-batch` once to find it,
then pass the result via `--batch-size`:

```text
Usage:
  vanityssh tune-batch [flags]

Flags:
  -d, --duration duration   benchmark duration per round per batch size (default 1s)
  -h, --help                help for tune-batch
  -j, --jobs int            number of parallel workers (default: number of CPUs)
```

Each candidate (powers of 2 from 2 to 512) is measured 3 rounds and the
median is used to reject OS scheduling noise. The winner is confirmed with a
longer run before being reported.

## Examples

Before starting a search, estimate how long it will take:

```bash
vanityssh estimate
```

Find the optimal batch size for your CPU, then use it:

```bash
vanityssh tune-batch
vanityssh --batch-size 64 'pattern$'
```

Find a key ending with "vanity" (case-insensitive):

```bash
vanityssh '(?i)vanity$'
```

Find a key ending with "dwd" (case-sensitive), continuous mode:

```bash
vanityssh -c 'dwd$'
```

Find a key whose SHA256 fingerprint starts with `0000`:

```bash
vanityssh -f '^0000'
```

Save keys to a specific directory:

```bash
vanityssh -o ~/my-keys 'pattern$'
```

Deterministic search — same passphrase always produces the same keys in the
same order, making long searches resumable across restarts:

```bash
vanityssh -p 'my secret passphrase' 'pattern$'
```

Resume a deterministic search from where it left off:

```bash
vanityssh -p 'my secret passphrase' --checkpoint progress.json 'pattern$'
```

Pipe the private key directly into a file:

```bash
vanityssh 'pattern$' > my_key
```

## Resource usage

vanityssh uses all available CPU cores by default. Use `-j` to limit workers.
With `--continuous` or a very difficult pattern, it will run until you press
Ctrl+C.

## License

[MIT](LICENSE)
