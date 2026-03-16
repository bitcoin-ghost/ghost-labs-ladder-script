# Ladder Script

Ladder Script is a condition system for Bitcoin, designed to address three challenges that will shape its future:

**Programmability** — Bitcoin needs richer spending policies. Multi-party custody, time-locked vaults, atomic swaps, and stateful contracts all require expressive conditions that compose cleanly. Ladder Script provides 60 block types across 10 families that can be combined freely — without the fragility of opcode sequences or the need to simulate execution to understand what a transaction does.

**Quantum Hardening** — Quantum computers will eventually break the elliptic curve cryptography that secures every Bitcoin address today. Ladder Script doesn't just plan for this — it ships with four working post-quantum signature schemes: FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+. They are implemented, tested, and running on the live signet right now. Any spending policy — single-sig, multisig, vaults, covenants — can use quantum-resistant keys today with zero structural changes.

**Data Abuse Mitigation** — Bitcoin's permissionless design has been exploited to embed arbitrary data on-chain, bloating the UTXO set and degrading network performance. Ladder Script closes these surfaces by design. Every byte in a transaction must conform to a declared type with enforced constraints. The node computes all hash commitments — users cannot write arbitrary data into condition fields.

Together, these three properties lead to a more scalable Bitcoin: smaller on-chain footprints, efficient encoding, and a chain free of data abuse.

---

## Get Started

- **[Ladder Script Overview](/labs/ladder-script.html)** — How it works, block families, MLSC, use cases
- **[Documentation](/labs/docs/)** — BIP spec, technical specification, block library, glossary
- **[Ladder Engine](/labs/engine/)** — Visual IDE: build, simulate, and broadcast transactions on the live signet
- **[Block Reference](/labs/docs/#BLOCKS)** — Deep-dive documentation on all 60 block types

## Signet

Ladder Script is fully implemented and running on a dedicated signet. Build transactions in the Engine, fund them from the signet faucet, and spend them — no local node required.
