# COMPACT_RUNG Implementation Plan

**Status:** Planned (not yet implemented)
**Depends on:** MPLC (complete), RUNG_TEMPLATE_INHERIT (complete on signet)
**Purpose:** Compact rung encoding for the most common single-block pattern (SIG). Eliminates block/field overhead, reducing wire size from ~64 bytes to 35 bytes per simple SIG rung.

## Motivation

In v3 RUNG_TX, every output requires ladder conditions. The most common pattern — a single SIG condition — currently needs a full rung with block headers, field descriptors, and coil metadata:

```
Full SIG rung breakdown (~64 bytes):
  n_blocks: varint(1)              1 byte
  micro-header: SIG                1 byte
  PUBKEY_COMMIT: 32 bytes         32 bytes   (implicit layout, no field count/type)
  SCHEME: 1 byte                   1 byte
  coil_type: uint8                 1 byte
  attestation: uint8               1 byte
  scheme: uint8                    1 byte
  address_len: varint              1 byte
  address: ~22 bytes              22 bytes   (P2WPKH witness program)
  n_coil_conditions: varint(0)     1 byte
  n_relays: varint(0)              1 byte
  n_rung_relay_refs: varint(1)     1 byte
  per-rung relay count: varint(0)  1 byte
                                  ─────────
  Total:                          ~64 bytes
```

This is excessive for change outputs, simple destinations, and happy-path rungs in multi-rung ladders. With MPLC, conditions are merkleized into the scriptPubKey — the full conditions are only revealed at spend time in the witness. Compact encoding reduces the witness cost for the legitimate spender without affecting output creation cost (which is a fixed-size Merkle root regardless).

### Spam Vector Analysis

Before MPLC, compact conditions would have reduced the scriptPubKey size, making it cheaper to create outputs (potential spam vector). After MPLC, the scriptPubKey is always a fixed-size Merkle root — compact encoding only reduces witness size at spend time. Since spammers create outputs but don't spend them, compact rungs provide no spam advantage.

A fake PUBKEY_COMMIT (hash that doesn't correspond to a real pubkey) creates an unspendable output, but this is equally true of full SIG rungs today. Compact encoding doesn't make it worse. Protection against UTXO spam comes from dust limits and transaction fees, both unaffected.

## Design

### COMPACT_SIG (type 0x01)

A standalone compact SIG condition with an explicit PUBKEY_COMMIT and scheme. Triggered by the `n_blocks == 0` sentinel within a rung.

```
COMPACT_SIG:
  [n_blocks: varint(0)]           ← sentinel: compact rung mode
  [compact_type: 0x01]            ← COMPACT_SIG
  [pubkey_commit: 32 bytes]       ← SHA-256 commitment to the public key
  [scheme: uint8]                 ← signature scheme (SCHNORR, ECDSA, PQ)
                                  ─────────
  Total:                          35 bytes
```

Savings vs full SIG rung: ~29 bytes (45% reduction).

Use cases:
- **Change outputs** — the primary motivation. Any output where the spending condition is just "the owner signs."
- **Simple destinations** — outputs going to a single recipient with no complex conditions.
- **Happy-path rungs** — in multi-rung ladders, the cooperative/optimistic path is often a single SIG.

### Coil Handling

Compact rungs do NOT include a coil — they inherit the coil from the parent LadderWitness. The coil is per-output (not per-rung), serialized once after all rungs. Compact rungs participate in rung evaluation like any other rung — they're just a more efficient encoding of a single-SIG condition.

### Witness Pairing

At spend time, the witness for a compact rung provides:

```
Compact rung witness (same structure as a normal SIG witness block):
  [PUBKEY: var]                   ← full public key (revealed at spend time)
  [SIGNATURE: var]                ← signature over the sighash
```

The evaluator:
1. Reads the PUBKEY_COMMIT from the compact rung data
2. Computes SHA-256(witness_PUBKEY), verifies it matches the commit
3. Verifies the signature against the pubkey using the specified scheme

This is identical to how `EvalSigBlock` works today.

## Wire Format Detail

### Sentinel: n_blocks == 0

Currently, `n_blocks == 0` is rejected in `DeserializeLadderWitness` (serialize.cpp line 408: "rung N has zero blocks"). This sentinel is safe to repurpose:

- No valid rung on chain has zero blocks
- The `n_rungs == 0` sentinel (used for template inherit / diff witness) is at a different level — it applies to the entire ladder, not individual rungs
- `n_blocks == 0` within a rung is a distinct signal that doesn't conflict

### Compact Type Byte

After `n_blocks == 0`, a single byte identifies the compact rung type:

| Byte | Type | Description |
|------|------|-------------|
| 0x01 | COMPACT_SIG | Standalone SIG with explicit PUBKEY_COMMIT + SCHEME |
| 0x02–0xFF | Reserved | Future compact types (see Future Extensions) |

## Data Structures

### New types (types.h)

```cpp
/** Compact rung types — efficient encodings for common single-block patterns.
 *  Triggered by n_blocks == 0 sentinel within a rung. */
enum class CompactRungType : uint8_t {
    COMPACT_SIG = 0x01,  //!< Single SIG with explicit PUBKEY_COMMIT + SCHEME
};

/** Returns true if the byte is a known CompactRungType. */
inline bool IsKnownCompactRungType(uint8_t b)
{
    return b == 0x01;
}

/** Compact rung data — stored in Rung when is_compact is true. */
struct CompactRungData {
    CompactRungType type;
    std::vector<uint8_t> pubkey_commit;  //!< 32-byte SHA-256(pubkey)
    RungScheme scheme{RungScheme::SCHNORR};
};
```

### Extended Rung (types.h)

```cpp
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};
    std::vector<uint16_t> relay_refs;
    std::optional<CompactRungData> compact;  // NEW

    bool IsCompact() const { return compact.has_value(); }  // NEW
};
```

## Deserialization (serialize.cpp)

In `DeserializeLadderWitness`, replace the `n_blocks == 0` error:

```cpp
if (n_blocks == 0) {
    // Compact rung mode
    uint8_t compact_type_byte;
    ss >> compact_type_byte;

    if (!IsKnownCompactRungType(compact_type_byte)) {
        error = "rung " + std::to_string(r) + " unknown compact type: 0x" +
                HexStr(std::span<const uint8_t>{&compact_type_byte, 1});
        return false;
    }

    CompactRungData compact;
    compact.type = static_cast<CompactRungType>(compact_type_byte);

    if (compact.type == CompactRungType::COMPACT_SIG) {
        // Read 32-byte PUBKEY_COMMIT
        compact.pubkey_commit.resize(32);
        ss.read(MakeWritableByteSpan(compact.pubkey_commit));
        // Read scheme byte
        uint8_t scheme_byte;
        ss >> scheme_byte;
        if (!IsKnownScheme(scheme_byte)) {
            error = "rung " + std::to_string(r) + " compact SIG unknown scheme";
            return false;
        }
        compact.scheme = static_cast<RungScheme>(scheme_byte);
    }

    ladder_out.rungs[r].compact = std::move(compact);
    continue; // next rung — no blocks to read
}
```

## Serialization (serialize.cpp)

In `SerializeLadderWitness`, add path for compact rungs:

```cpp
for (const auto& rung : ladder.rungs) {
    if (rung.IsCompact()) {
        WriteCompactSize(ss, 0); // sentinel: n_blocks == 0
        ss << static_cast<uint8_t>(rung.compact->type);

        if (rung.compact->type == CompactRungType::COMPACT_SIG) {
            ss.write(AsBytes(std::span{rung.compact->pubkey_commit}));
            ss << static_cast<uint8_t>(rung.compact->scheme);
        }
        continue;
    }
    // ... existing block serialization
}
```

## Resolution (evaluator.cpp)

New function to resolve a compact rung into an equivalent SIG block for evaluation:

```cpp
bool ResolveCompactRung(const Rung& rung,
                        RungBlock& resolved_block,
                        std::string& error)
{
    if (!rung.IsCompact()) {
        error = "not a compact rung";
        return false;
    }

    const auto& compact = *rung.compact;
    resolved_block.type = RungBlockType::SIG;
    resolved_block.inverted = false;

    if (compact.type == CompactRungType::COMPACT_SIG) {
        resolved_block.fields.push_back({RungDataType::PUBKEY_COMMIT, compact.pubkey_commit});
        resolved_block.fields.push_back({RungDataType::SCHEME,
            {static_cast<uint8_t>(compact.scheme)}});
    }

    return true;
}
```

## Integration into EvalLadder (evaluator.cpp)

In the rung evaluation loop, before evaluating blocks:

```cpp
for (size_t r = 0; r < ladder.rungs.size(); ++r) {
    const auto& rung = ladder.rungs[r];

    if (rung.IsCompact()) {
        // Resolve compact rung to equivalent SIG block
        RungBlock resolved;
        std::string resolve_error;
        if (!ResolveCompactRung(rung, resolved, resolve_error)) {
            // Resolution failure — rung fails
            continue;
        }
        // Evaluate as single-block rung
        EvalResult result = EvalBlock(resolved, checker, sigversion, execdata);
        if (result == EvalResult::SATISFIED) {
            // This rung passes — first satisfied rung wins (OR logic)
            satisfied_rung = r;
            break;
        }
        continue;
    }

    // ... existing block-by-block evaluation
}
```

## MLSC (Merkleized Ladder Script Conditions) Integration

Compact rungs participate in the MLSC Merkle tree normally. Each compact rung is a leaf in the rung-level Merkle tree. The leaf hash is computed from the compact wire encoding:

```cpp
// In MerkleHashRung():
if (rung.IsCompact()) {
    // Serialize compact rung data for hashing
    DataStream ss{};
    WriteCompactSize(ss, 0); // sentinel
    ss << static_cast<uint8_t>(rung.compact->type);
    if (rung.compact->type == CompactRungType::COMPACT_SIG) {
        ss.write(AsBytes(std::span{rung.compact->pubkey_commit}));
        ss << static_cast<uint8_t>(rung.compact->scheme);
    }
    // Hash with tagged hash
    return TaggedHash("LadderRung", ss);
}
```

A compact rung is self-contained — no dependencies on other rungs or outputs. MLSC can prune all non-revealed rungs normally.

## Validation Rules

| Rule | Rationale |
|------|-----------|
| `n_blocks == 0` followed by known compact type | Sentinel reuse — currently rejected, safe to repurpose |
| COMPACT_SIG: pubkey_commit exactly 32 bytes | Matches PUBKEY_COMMIT field size constraint |
| COMPACT_SIG: scheme must be known | Same validation as full SIG blocks |
| Unknown compact type byte rejected | Forward compatibility — new types added via soft fork |
| Compact rung has no relay_refs | Compact rungs are standalone — relay composition requires full rungs |

## Policy Updates (policy.cpp)

`IsStandardRungTx` updated to:
- Recognise compact rung format (`n_blocks == 0` with valid compact type)
- Apply same size/count limits
- Reject unknown compact type bytes (forward compatibility)

`IsStandardRungConditions` updated similarly for conditions-side validation.

## Tests (rung_tests.cpp)

| # | Test | Purpose |
|---|------|---------|
| 1 | `compact_sig_roundtrip` | Serialize/deserialize COMPACT_SIG, verify fields |
| 2 | `compact_sig_evaluation` | Full spend with COMPACT_SIG condition + SIG witness |
| 3 | `compact_sig_schnorr` | COMPACT_SIG with SCHNORR scheme |
| 4 | `compact_sig_ecdsa` | COMPACT_SIG with ECDSA scheme |
| 5 | `compact_sig_pq` | COMPACT_SIG with PQ scheme (FALCON512) |
| 6 | `compact_sig_rejects_wrong_commit_size` | pubkey_commit != 32 bytes rejected |
| 7 | `compact_sig_rejects_unknown_scheme` | Unknown scheme byte rejected |
| 8 | `compact_sig_unknown_compact_type` | Unknown compact type byte rejected |
| 9 | `compact_sig_mlsc_merkle` | Compact rung produces correct MLSC leaf hash |
| 10 | `compact_sig_wire_size` | Verify COMPACT_SIG is 35 bytes on the wire |
| 11 | `compact_rung_mixed_ladder` | Ladder with both compact and full rungs evaluates correctly |
| 12 | `compact_rung_as_change` | Full tx: normal output + compact SIG change output |
| 13 | `compact_rung_combined_template_inherit` | Compact rung + template inheritance on same input |
| 14 | `compact_rung_no_relay_refs` | Compact rung with relay_refs rejected |

## Files Touched

| File | Change |
|------|--------|
| `types.h` | CompactRungType enum, CompactRungData struct, compact field on Rung, IsCompact() |
| `serialize.cpp` | Compact rung deserialize/serialize paths (n_blocks == 0 branch) |
| `serialize.h` | No change (constants unchanged) |
| `evaluator.cpp` | ResolveCompactRung + compact branch in EvalLadder |
| `conditions.cpp` | Compact rung support in MLSC Merkle leaf hashing |
| `policy.cpp` | Recognise compact rungs in standardness checks |
| `rpc.cpp` | Display compact rungs in decoderung / decoderungwitness |
| `rung_tests.cpp` | 14 new tests |

## Breakage Analysis

No breakage to existing code. Full analysis:

- **Sentinel (n_blocks == 0):** Currently rejected in rung deserializer. Safe to repurpose — no valid rung on chain has zero blocks. Distinct from `n_rungs == 0` (template/diff witness) which operates at the ladder level.
- **EvalLadder:** Compact rungs resolve to standard SIG blocks before evaluation. All downstream evaluation logic (commit verification, scheme dispatch, PQ support) unchanged.
- **MergeConditionsAndWitness:** Resolved compact rung is structurally identical to a full SIG rung. No change needed.
- **Sighash:** Commits to conditions Merkle root. Compact rungs have a defined Merkle leaf hash. Unaffected.
- **Template inheritance:** Compact rungs can be inherited via template reference. The compact encoding is preserved in the inherited conditions.
- **Diff witness:** Diffs can target fields within resolved compact rungs (the PUBKEY and SIGNATURE witness fields).
- **Existing tests:** No existing test exercises `n_blocks == 0` within a rung. No breakage.
- **Wire compatibility:** Expansion of valid set (soft-fork pattern).

## Savings Estimate

| Scenario | Full SIG Rung | COMPACT_SIG | Savings |
|----------|---------------|-------------|---------|
| Change output | ~64 bytes | 35 bytes | 45% |
| 3-rung ladder (2 full + 1 compact change) | ~192 bytes | ~163 bytes | 15% |
| Covenant chain hop (change per hop) | ~128 bytes/hop | ~99 bytes/hop | 23% |
| Two simple SIG outputs | ~128 bytes | ~70 bytes | 45% |

Combined with RUNG_TEMPLATE_INHERIT and DIFF_WITNESS, a full covenant chain hop with compact change drops from ~300+ bytes to ~100 bytes total.

## Future Extensions

The compact type byte reserves 0x02–0xFF for future compact rung types:

| Type | Potential Use |
|------|--------------|
| 0x02 | KEY_REF_SIG — SIG referencing a PUBKEY_COMMIT from another source (requires cross-output reference design; deferred due to MLSC interaction complexity — see below) |
| 0x03 | COMPACT_MULTISIG — M-of-N with inline pubkey commits |
| 0x04 | COMPACT_CSV_SIG — SIG + relative timelock (common pattern) |
| 0x05 | COMPACT_HTLC — hash + timelock + sig (Lightning/atomic swaps) |

These would follow the same pattern: `n_blocks == 0` + type byte + minimal fields. Each new compact type would need its own design doc and test suite.

### KEY_REF_SIG Deferral Note

KEY_REF_SIG (referencing a PUBKEY_COMMIT from another rung) was considered but deferred due to scope issues:

1. **Within same output:** Conditions are per-output. A change output has its own conditions with typically only one rung — there's nothing else in the change output's ladder to reference. KEY_REF_SIG within the same output only helps multi-rung ladders where multiple rungs reuse a key.

2. **Cross-output reference:** Referencing a key from another output's conditions would require cross-output dependencies. Each output's conditions are independently merkleized into separate scriptPubKeys. Cross-output references complicate MLSC proofs and independent output evaluation.

3. **MLSC pruning:** If the referenced rung is pruned from the Merkle proof (because a different rung is being spent), the evaluator can't resolve the reference without also revealing the referenced rung — adding bytes and defeating MLSC's privacy benefit.

COMPACT_SIG at 35 bytes is sufficient for the primary use case (change outputs). KEY_REF_SIG's additional savings (~30 bytes) don't justify the architectural complexity until cross-output references are designed.
