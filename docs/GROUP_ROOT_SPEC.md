# Group Root Outputs — Specification

**Status:** Draft · March 2026

---

## Overview

Group root outputs replace per-output MLSC scriptPubKeys with a single
transaction-level commitment to all output conditions. Each output stores only
a value and an index. The conditions roots for all outputs are leaves of a
Merkle tree whose root appears once in the transaction.

This achieves two goals:

1. **Anti-spam.** Attacker-chosen data drops from `N × 32` bytes (one root per
   output) to 32 bytes per transaction (one group root). Combined with
   `MAX_PREIMAGE_FIELDS_PER_TX = 2`, the total embeddable surface is ~159 bytes
   per transaction regardless of input or output count.

2. **Fee reduction.** Outputs shrink from 42 bytes (8 value + 1 varint + 33
   scriptPubKey) to 9 bytes (8 value + 1 index). A 100-output batch transaction
   drops from 4,200 bytes to 932 bytes — 78% smaller.

---

## Wire Format

### Transaction structure (v4 RUNG_TX)

```
nVersion        : int32    (= 4)
vin_count       : varint
vin[]           : [prevout(36) + scriptSig(varint+data) + nSequence(4)]
vout_count      : varint
outputs_root    : 32 bytes    ← NEW: Merkle root of all output conditions
vout[]          : [nValue(8) + output_index(1)]    ← CHANGED: no scriptPubKey
nLockTime       : uint32
witness[]       : per-input witness stacks
```

### Output format

Each output is 9 bytes:

```
nValue       : int64     (8 bytes, little-endian satoshi amount)
output_index : uint8     (0-based position in the group tree)
```

No `scriptPubKey` field. The spending conditions for each output are committed
via the group root.

### Maximum outputs

`output_index` is `uint8`: maximum **255 outputs** per transaction (index 0–254,
index 255 reserved for DATA_RETURN). This covers all practical use cases
(exchange batches, pool payouts, recursive splits) while bounding transaction
size.

### DATA_RETURN outputs

DATA_RETURN outputs use `output_index = 0xFF` (255), must have `nValue = 0`,
and carry an optional payload:

```
nValue       : int64     (must be 0)
output_index : uint8     (0xFF)
payload_len  : varint    (0–40 bytes)
payload      : bytes
```

Maximum 1 DATA_RETURN output per transaction (consensus).

---

## Group Tree Construction

The group tree is a binary Merkle tree built from the individual output
conditions roots:

```
leaf[i] = SHA256( output_index || conditions_root[i] )
```

where `output_index` is the 1-byte index and `conditions_root[i]` is the
32-byte MLSC Merkle root of output `i`'s conditions tree.

Interior nodes:

```
node = SHA256( min(left, right) || max(left, right) )
```

Sorted interior nodes (same algorithm as MLSC conditions tree) for canonical
ordering.

The `outputs_root` in the transaction is the root of this tree.

**Single output:** `outputs_root = leaf[0]` (degenerate tree, no proof needed
at spend time — the leaf IS the root).

**Two outputs:** `outputs_root = SHA256(min(leaf[0], leaf[1]) || max(leaf[0], leaf[1]))`.

---

## UTXO Set Entry

Each output is stored in the UTXO set as:

```
outputs_root  : 32 bytes    (from the creating transaction)
output_index  : 1 byte      (from the output)
nValue        : 8 bytes     (from the output)
```

Total: **41 bytes** per UTXO entry. Current MLSC: 33 (scriptPubKey) + 8
(value) = 41 bytes. **Identical size.**

---

## Spending

When spending output `i`, the witness stack contains:

```
stack[0] : LadderWitness          (rung blocks + fields)
stack[1] : MLSCProof              (conditions tree proof)
stack[2] : GroupProof             (output tree proof)  ← NEW
```

### GroupProof format

```
conditions_root  : 32 bytes    (the individual MLSC root for this output)
proof_count      : varint      (number of sibling hashes, = ceil(log2(N)))
proof_hashes[]   : 32 bytes each
```

### Verification (VerifyRungTx)

1. Deserialize `GroupProof` from `stack[2]`.
2. Compute `leaf = SHA256(output_index || conditions_root)`.
3. Walk `proof_hashes` using sorted interior node construction.
4. Verify computed root == `outputs_root` (from UTXO set entry).
5. Proceed with standard MLSC proof verification against `conditions_root`.

**Single-output optimisation:** If the creating transaction had exactly 1
non-DATA_RETURN output, `stack[2]` may be empty (0 bytes). The verifier
computes `leaf[0]` directly and checks it equals `outputs_root`. No proof
hashes needed.

---

## Consensus Dust Threshold

v4 transactions enforce a **minimum output value at consensus**:

```cpp
static constexpr CAmount MIN_RUNG_OUTPUT_VALUE = 546;  // satoshis
```

### Rules

1. Every non-DATA_RETURN output must have `nValue >= MIN_RUNG_OUTPUT_VALUE`.
2. DATA_RETURN outputs must have `nValue == 0`.
3. Checked in `ValidateRungOutputs()` at consensus (not just policy).

### Rationale

Bitcoin enforces dust as a standardness/policy rule. Miners can bypass it.
For v4 transactions, consensus-level enforcement prevents:

- UTXO set bloat from sub-economic outputs
- Cheap output-layer spam (each output costs at minimum 546 sats)
- Miners including their own spam transactions

Combined with group root (32 bytes per tx) and per-tx preimage cap (64 bytes
per tx), the cost of data embedding becomes:

```
546 sats per output × ceil(data_bytes / 32) outputs
+ transaction fee
+ data is limited to 32 bytes total (group root)
```

An attacker wanting to embed 32 bytes of data must burn at minimum 546 sats
(one output) plus fees. For comparison, an OP_RETURN on legacy Bitcoin embeds
80 bytes for the cost of fees alone.

### Future adjustment

`MIN_RUNG_OUTPUT_VALUE` is a consensus constant. Changing it requires a
softfork. The value 546 matches the current Bitcoin dust threshold for
witness outputs. If a future fee environment makes this too high or too low,
it can be adjusted via the same softfork mechanism used for any consensus
parameter.

---

## Impact on Existing Block Types

### RECURSE_* (recursive covenants)

Recursive blocks verify that output conditions match expected roots. With
group root outputs, the verifier:

1. Computes the expected `conditions_root` for the recursive output.
2. Verifies that `conditions_root` appears as a leaf of `outputs_root`
   using the `GroupProof` provided in the spending witness.

No change to the recursive block evaluation logic itself — only the output
matching step wraps through the group tree.

### CTV (CheckTemplateVerify)

CTV commits to a transaction template. The template hash computation changes:

**Current:** template includes per-output scriptPubKeys.
**New:** template includes `outputs_root` (32 bytes, once) + per-output
`nValue` and `output_index`.

CTV becomes more efficient: the template hash is smaller for multi-output
templates.

### OUTPUT_CHECK (per-output constraint)

OUTPUT_CHECK verifies `script_hash` against a specific output. With group
root, `script_hash` is verified against the `conditions_root` leaf for that
output index (accessed via group tree proof). The `output_index` NUMERIC
parameter maps directly to the group tree leaf.

### COSIGN (cross-input constraint)

COSIGN constrains the scriptPubKey of a co-spent input. With group root,
the "scriptPubKey" is effectively `outputs_root || output_index`. The
COSIGN hash computation updates accordingly.

---

## Size Comparison

### Transaction output bytes

| Outputs | Current (42B each) | Group root (32 + 9B each) | Saving |
|---------|-------------------:|-------------------------:|-------:|
| 1       | 42                 | 41                        | 2%     |
| 2       | 84                 | 50                        | 40%    |
| 5       | 210                | 77                        | 63%    |
| 10      | 420                | 122                       | 71%    |
| 50      | 2,100              | 482                       | 77%    |
| 100     | 4,200              | 932                       | 78%    |
| 200     | 8,400              | 1,832                     | 78%    |

### Spend witness overhead

| Outputs in creating tx | Extra witness bytes (GroupProof) |
|------------------------|---------------------------------|
| 1                      | 0 (single-output optimisation)  |
| 2                      | 32 + 1 + 32 = 65               |
| 4                      | 32 + 1 + 64 = 97               |
| 8                      | 32 + 1 + 96 = 129              |
| 16                     | 32 + 1 + 128 = 161             |
| 100                    | 32 + 1 + 224 = 257             |
| 255                    | 32 + 1 + 256 = 289             |

The extra spend cost is small: ~33 bytes for conditions_root + 32 bytes per
tree level. A 100-output transaction adds ~257 bytes to each spend witness.

### Net effect

For the creating transaction: large savings (78% for 100 outputs).
For spending: small overhead (~257 bytes worst case).
Net: strongly positive for batch-heavy use cases.

---

## Anti-Spam Summary

| Attack Vector | Current | With Group Root |
|---|---|---|
| Output roots (per-output data) | N × 32 bytes | 32 bytes (flat) |
| PREIMAGE data (multi-input) | N × 32 bytes | 64 bytes (flat, per-tx cap) |
| Witness fields | ~52 bytes | ~52 bytes (unchanged) |
| Standard tx fields | ~8 bytes | ~8 bytes (unchanged) |
| Nonce grinding | ~3 bytes | ~3 bytes (unchanged) |
| **Total per transaction** | **Scales with N** | **~159 bytes (flat)** |

No scaling attack exists. The embeddable surface is fixed regardless of
transaction complexity.

---

## Implementation Checklist

### serialize.h / serialize.cpp
- [ ] Add `MAX_OUTPUTS_PER_RUNG_TX = 255`
- [ ] Add `MIN_RUNG_OUTPUT_VALUE = 546`
- [ ] New serialisation for v4 output format (value + index, no scriptPubKey)
- [ ] `outputs_root` field in transaction serialisation
- [ ] `GroupProof` deserialisation

### conditions.cpp
- [ ] `BuildGroupTree()` — Merkle tree from individual conditions roots
- [ ] `VerifyGroupProof()` — verify leaf membership in group tree

### evaluator.cpp
- [ ] `ValidateRungOutputs()` — enforce dust threshold, max 255 outputs
- [ ] `VerifyRungTx()` — deserialize and verify GroupProof from stack[2]
- [ ] Update CTV template hash computation
- [ ] Update OUTPUT_CHECK evaluation
- [ ] Update COSIGN evaluation
- [ ] Update RECURSE_* output matching

### rpc.cpp
- [ ] Update `signrungtx` / `signladder` to build group tree
- [ ] Update `createrungtx` to emit new output format
- [ ] Update `decoderungtx` to display group root

### Tests
- [ ] Group tree construction and proof verification unit tests
- [ ] Single-output optimisation test
- [ ] DATA_RETURN with group root test
- [ ] Dust threshold consensus test
- [ ] RECURSE_* through group root test
- [ ] CTV template hash with group root test
- [ ] 255-output boundary test

---

*Group Root Outputs Specification v0.1 · Bitcoin Ghost Project · March 2026*
