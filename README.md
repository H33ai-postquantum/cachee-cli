# Cachee CLI

**The world's first post-quantum caching service.**

Every entry carries a 58-byte Substrate receipt signed by 3 independent post-quantum signature families (ML-DSA-65, FALCON-512, SLH-DSA). Cache poisoning is cryptographically impossible.

## Install

```bash
# Homebrew (macOS/Linux)
brew install h33ai/tap/cachee

# Cargo
cargo install cachee-cli

# Docker
docker run -p 6380:6380 h33ai/cachee
```

## Quick start

```bash
# Initialize — creates config + generates PQ keypair
cachee init

# Start the daemon (RESP protocol on port 6380)
cachee start

# Use it (Redis-compatible)
cachee set mykey "hello world"
cachee get mykey

# Enable PQ attestation (Substrate signing on every SET)
cachee attest enable

# Run built-in benchmark
cachee bench
```

## Commands

| Command | Description |
|---|---|
| `cachee init` | Create config, generate PQ identity |
| `cachee start` | Start RESP daemon |
| `cachee stop` | Stop daemon |
| `cachee status` | Show stats, hit rate, memory |
| `cachee set KEY VALUE` | Store a value |
| `cachee get KEY` | Retrieve a value |
| `cachee del KEY` | Delete a value |
| `cachee attest enable` | Enable PQ attestation on all writes |
| `cachee attest status` | Show attestation config |
| `cachee bench` | Run throughput/latency benchmark |
| `cachee cluster join` | Join D-Cachee federation |

## Architecture

- **L0 hot tier**: Sharded RwLock HashMap (~28ns reads)
- **L1**: DashMap concurrent HashMap
- **CacheeLFU**: Admission control via frequency sketch
- **RESP protocol**: Drop-in Redis replacement
- **PQ attestation**: 58-byte Substrate receipt per entry (optional)
- **On-chain anchor**: 74 bytes — fits Bitcoin OP_RETURN, Solana memo, Ethereum calldata

## Performance

```
Cachee Benchmark (4 workers, M4 Max)
  Throughput : 3,264,445 ops/sec
  Latency    : 0.306 µs/op
  Hit rate   : 100%
  L0 hits    : 13,062,648
```

## Learn more

- [Product page](https://cachee.ai/pq-cache)
- [H33 Substrate patent](https://h33.ai/substrate)

---

H33.ai, Inc. · Eric Beans, CEO
