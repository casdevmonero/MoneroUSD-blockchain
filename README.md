# MoneroUSD (USDm)

**MoneroUSD** is a private stablecoin built on Monero's privacy technology with **FCMP++ (Full-Chain Membership Proofs)** — the most advanced transaction privacy system in cryptocurrency.

Website: [monerousd.org](https://monerousd.org)

## What is MoneroUSD?

MoneroUSD (USDm) is a privacy-first stablecoin where every transaction is shielded by default. Unlike transparent stablecoins like USDT or USDC, USDm transactions hide the sender, receiver, and amount using:

- **FCMP++** — Full-Chain Membership Proofs that reference the entire blockchain as the anonymity set, making transaction graph analysis virtually impossible
- **RingCT** — Confidential transactions that hide amounts
- **Stealth Addresses** — One-time addresses that prevent address linkage
- **Bulletproofs+** — Efficient range proofs for confidential amounts

## Features

- **Private stablecoin** — Every USDm transaction is shielded by default
- **FCMP++ privacy** — Full-chain membership proofs (entire UTXO set as anonymity set)
- **BTC/XMR backed** — USDm is minted through verified BTC and XMR collateral deposits
- **Atomic swaps** — Swap between BTC, XMR, and USDm
- **Staking** — Earn yield by locking USDm (1.5%–6% APR)
- **Lending** — Borrow USDm against BTC/XMR collateral
- **CPU mining** — Proof-of-work using RandomX (ASIC-resistant)
- **Cross-platform wallet** — Desktop (Windows/macOS/Linux) and browser

## Building from source

### Dependencies

- CMake 3.5+
- GCC 7+ or Clang 6+
- Boost 1.58+
- OpenSSL
- libsodium
- Rust toolchain (for FCMP++ FFI)

### Build

```bash
git clone --recursive https://github.com/casdevmonero/MoneroUSD-blockchain.git
cd MoneroUSD-blockchain
make release -j$(nproc)
```

Binaries will be in `build/release/bin/`:
- `USDmd` — Full node daemon
- `USDm-wallet-rpc` — Wallet RPC server
- `USDm-wallet-cli` — Command-line wallet

### macOS

```bash
make release -j$(sysctl -n hw.logicalcpu)
```

### Windows (MSYS2)

```bash
make release-static-win64
```

## Running a node

```bash
./USDmd --add-peer seed.monerousd.org:17749
```

### Default ports

| Service | Port |
|---------|------|
| P2P | 17749 |
| RPC | 17750 |
| ZMQ | 17751 |

### Running with wallet RPC

```bash
./USDm-wallet-rpc \
  --rpc-bind-port 27750 \
  --daemon-address localhost:17750 \
  --wallet-dir ~/monerousd-wallets \
  --disable-rpc-login
```

## Network

- **Consensus:** Proof-of-Work (RandomX)
- **Block time:** ~120 seconds
- **Privacy:** FCMP++ (full-chain membership proofs)
- **Address prefix:** `Mo` (mainnet), `MJ` (Seraphis)

## Wallet

The desktop wallet is available at [monerousd.org](https://monerousd.org) or from the [wallet repository](https://github.com/casdevmonero/MoneroUSD).

## License

See [LICENSE](LICENSE).

Portions Copyright (c) 2014-2024 The Monero Project.
Portions Copyright (c) 2012-2013 The Cryptonote developers.
