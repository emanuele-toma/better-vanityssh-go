# better-vanityssh-go

Generate ED25519 SSH key pairs at high speed and match the resulting public
keys (or SHA256 fingerprints) against a regex pattern.

## Performance improvements over the original

This fork adds several performance and usability improvements on top of the
[original vanityssh-go](https://github.com/danielewood/vanityssh-go).

### Montgomery batch point compression (~22% throughput gain)

Key generation throughput in random mode was improved by batching 16 Ed25519
keys per iteration and compressing their curve points together using a single
field inversion (Montgomery's trick) instead of one per key.

Measured on AMD Ryzen 7 3800X (16 logical cores):

| Operation | ns/key | keys/sec/core |
|---|---|---|
| Single key (baseline) | 33,575 | ~29,800 |
| Batch 16 keys | 25,990 | ~38,500 |
| **Improvement** | **−22.6%** | **+29%** |

The compression step specifically drops from **5,711 ns/point** to **544 ns/point**
(~10.5× speedup) by amortizing one field inversion across 16 points.

### `make build` output

`make build` produces a `vanityssh-go` binary in the current directory (the
project root). The GoReleaser binary name used in releases is `vanityssh`.

## Is it safe to use?

Yes. Key generation uses Go's `crypto/ed25519` and `crypto/rand` from the
standard library. vanityssh does not implement any cryptography itself — it
generates keys using the same functions as `ssh-keygen` and filters the
output. Private keys are serialized with `golang.org/x/crypto/ssh.MarshalPrivateKey`
in the current OpenSSH format.

## Installation

### From releases

Download a prebuilt binary from the
[releases page](https://github.com/emanueletoma/better-vanityssh-go/releases).

### From source

```bash
go install github.com/emanueletoma/better-vanityssh-go@latest
```

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
in the current directory (or the directory given by --output). Use
--continuous to keep finding keys.

When piping, only the private key is written to stdout.

Usage:
  vanityssh <regex> [flags]

Flags:
  -c, --continuous          keep finding keys after a match
  -f, --fingerprint         match against SHA256 fingerprint instead of public key
  -h, --help                help for vanityssh
  -j, --jobs int            number of parallel workers (default: number of CPUs)
  -o, --output string       directory to save key files (default: current directory)
  -p, --passphrase string   derive deterministic seed via Argon2id (enables reproducible key generation)
      --checkpoint string   checkpoint file path for saving/resuming progress (requires --passphrase)
  -v, --version             version for vanityssh
```

## Examples

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
