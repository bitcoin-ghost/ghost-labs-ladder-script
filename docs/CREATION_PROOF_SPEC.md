# Creation Proof — Specification

**Status:** Draft · March 2026

---

## Overview

A creation proof is a witness-carried proof that each output's MLSC root was
derived from valid, typed conditions. It closes the gap between our node
(which builds roots from validated conditions) and consensus (which currently
accepts any 32 bytes after 0xC2).

The output format does not change. The UTXO set does not change. The spending
flow does not change. The only addition: a creation proof section in the
creating transaction's witness, validated at block acceptance time.

---

## Problem Statement

Current system:

```
Our node: conditions → deserializer validates → computes root → output
Consensus: sees 0xC2 + 32 bytes → accepts on format alone
```

An attacker bypasses the node, crafts raw bytes, puts arbitrary 32 bytes
after 0xC2. Consensus cannot distinguish real roots from garbage. Garbage
roots persist in the UTXO set permanently if never spent.

---

## Design

### Output format (UNCHANGED)

```
0xC2 | 32-byte MLSC root
```

Identical to current. No changes to scriptPubKey format, UTXO set entries,
or output serialization.

### Witness format (EXTENDED)

The creating transaction's witness gains a creation proof section after the
normal per-input spending witnesses.

```
witness stack per input:
  stack[0]: LadderWitness      (spending proof — unchanged)
  stack[1]: MLSCProof          (conditions proof — unchanged)

creation proof section (once per transaction, after all input witnesses):
  n_output_proofs: varint      (must equal number of MLSC outputs)
  per output:
    n_rungs: varint
    per rung:
      structural_template:     (block types + inverted flags + field layout)
      value_commitment: 32B    (Hash(field_values || pubkeys))
```

### Structural template format

Per rung:

```
n_blocks:    varint
per block:
  block_type:  uint16      (2 bytes — must be known type)
  inverted:    uint8       (0x00 or 0x01 — must be valid for this type)
coil:
  coil_type:   uint8       (UNLOCK, UNLOCK_TO, COVENANT)
  attestation: uint8       (INLINE, AGGREGATE, DEFERRED)
  scheme:      uint8       (signature scheme)
  has_address: uint8       (0 or 1)
```

Field types and counts are NOT in the template — they are derived from the
block type via implicit layouts (same as deserialization). The deserializer
validates that the block type has a known implicit layout and that the
template is consistent.

Typical size per rung: ~8-12 bytes.

### Value commitment

```
value_commitment = SHA256(field_value_0 || field_value_1 || ... || pubkey_0 || pubkey_1 || ...)
```

All field values concatenated in layout order, followed by all pubkeys for
the rung (merkle_pub_key). The commitment is 32 bytes. It binds the rung's
private data without revealing it.

### Leaf computation

```
rung_leaf = TaggedHash("LadderLeaf", structural_template || value_commitment)
```

Same tagged hash as current MLSC leaf computation, but with the template and
commitment as inputs instead of full conditions + pubkeys.

### Root verification

At block validation, for each MLSC output in a v4 transaction:

1. Read the creation proof for this output from the witness.
2. For each rung: validate structural_template (known block types, valid
   inversion, valid coil). Reject if any check fails.
3. Compute rung_leaf for each rung from template + value_commitment.
4. Build Merkle tree from rung_leaves (same sorted interior node algorithm).
5. Verify computed root == the 32-byte root in the output scriptPubKey.
6. If mismatch: reject transaction.

If a v4 transaction has MLSC outputs but no creation proof: reject.

---

## Size Impact

### Per-rung creation proof data

```
structural_template: ~10 bytes
value_commitment:     32 bytes
total per rung:      ~42 bytes (in witness, 1/4 weight)
```

### Transaction weight impact

Simple payment (1 input, 2 outputs, 1 rung per output):

```
Current:   670 WU
With proof: 670 + (2 × 42 × 1) = 670 + 84 = 754 WU  (but see note below)
```

Note: the creation proof is in the witness section. If it is part of the
segregated witness (weight = 1 WU per byte), the impact is:

```
Extra: 2 rungs × 42 bytes × 1 WU = 84 WU
Total: 670 + 84 = 754 WU = 189 vB
Fee increase: ~21 sats at 10 sat/vB
```

Wait — the creation proof might qualify for a further discount since it is
purely validation data (not needed after initial verification). For now we
assume standard witness weight (1 WU per byte).

### Comparison across transaction types

| Transaction | Current WU | With proof WU | Extra fee (10 sat/vB) |
|---|---|---|---|
| Simple (1→2, 1 rung/out) | 670 | 754 | +21 sats |
| Simple (1→2, 2 rungs/out) | 702 | 870 | +42 sats |
| Batch (1→10, 1 rung/out) | 2,014 | 2,434 | +105 sats |
| Batch (1→100, 1 rung/out) | 17,134 | 21,334 | +1,050 sats |
| Consolidation (5→1, 1 rung) | 1,646 | 1,688 | +11 sats |
| CoinJoin (5→5, 1 rung/out) | 2,318 | 2,528 | +53 sats |

---

## Security Analysis

### Attack 1: Embed readable data in MLSC root

**Goal:** Put a chosen 32-byte message M in an output root.

**With creation proof:** Root = MerkleRoot(leaves), where each
leaf = TaggedHash("LadderLeaf", validated_template || value_commitment),
and value_commitment = SHA256(field_values || pubkeys).

To make root = M: attacker must find inputs where
Hash(Hash(validated_template || Hash(values || pubkeys))) = M.
This requires inverting SHA256 — 2^256 work. **Infeasible.**

**Verdict: BLOCKED.**

### Attack 2: Embed readable data in value_commitment

**Goal:** Put a chosen 32-byte message M in a value_commitment in the witness.

**With creation proof:** value_commitment = SHA256(field_values || pubkeys).
To make this equal M: find field_values and pubkeys where SHA256(concat) = M.
This is a preimage attack — 2^256 work. **Infeasible.**

The attacker can choose field_values and pubkeys, but the resulting
commitment is a hash output, not their chosen input.

**Verdict: BLOCKED.**

### Attack 3: Embed readable data in structural templates

**Goal:** Put arbitrary bytes in the structural template section.

**With creation proof:** Templates are validated:
- block_type must be in the known set (61 types) — 2 bytes, ~6 bits of freedom
- inverted must be 0x00 or 0x01 — 1 bit
- coil fields are constrained enums

Per rung: ~3-4 bits of attacker freedom in validated fields.
For 100 rungs: ~400 bits = 50 bytes of steganographic capacity.

But this is enum-constrained — block_type must be one of 61 known values.
The attacker cannot encode arbitrary byte sequences, only choose from valid
block types. The encoding bandwidth is extremely low and requires
combinatorial grinding.

**Verdict: NEGLIGIBLE.** ~50 bytes across 100 rungs, not freely chosen,
requires grinding, not readable without the attacker's codebook.

### Attack 4: Create valid but unspendable outputs (UTXO bloat)

**Goal:** Fill the UTXO set with outputs nobody will ever spend.

**With creation proof:** Attacker creates valid templates (e.g. SIG with
SCHNORR scheme), valid value_commitments (hash of random pubkey), valid
root. Transaction accepted. Output goes in UTXO set.

The output has a valid root derived from a real SIG block — but the pubkey
is random. Nobody can spend it. It stays in the UTXO forever.

**Cost:** 546 sats per output (consensus dust threshold).
**Data embedded:** 0 readable bytes (root is a hash output).
**UTXO impact:** 40 bytes per entry (same as any legitimate output).

**Verdict: NOT BLOCKED but economically constrained.** Same as creating a
Taproot output to a random key. The creation proof ensures the root is
protocol-derived (not arbitrary data), but cannot prevent unspendable
outputs. Dust threshold is the defense.

### Attack 5: Skip the creation proof

**Goal:** Submit a v4 transaction without creation proof data.

**With creation proof:** Consensus rejects any v4 transaction with MLSC
outputs that lacks a valid creation proof section. The transaction is
invalid and will not be relayed or mined.

**Verdict: BLOCKED.**

### Attack 6: Provide mismatched creation proof

**Goal:** Provide valid-looking templates but a root that doesn't match.

**With creation proof:** The verifier recomputes the root from templates +
value_commitments and checks it matches the output. Mismatch = reject.

**Verdict: BLOCKED.**

### Attack 7: Reuse templates across outputs to embed data in output ordering

**Goal:** Encode data in which outputs have which templates.

**With creation proof:** The attacker can choose which templates to assign
to which outputs. With 61 block types and N outputs, the ordering encodes
~log2(61^N) bits = ~6N bits.

For 100 outputs: ~600 bits = 75 bytes of steganographic capacity in the
ordering. But this requires the attacker's codebook to decode and is not
readable by third parties.

**Verdict: NEGLIGIBLE.** Low bandwidth, requires codebook, not directly
readable.

### Attack 8: Use DATA_RETURN outputs to embed data

**Goal:** Use the DATA_RETURN mechanism for spam.

**Existing defense:** DATA_RETURN outputs are already limited to:
- Maximum 1 per transaction
- Maximum 40 bytes payload
- Must have zero value (unspendable)
- Legitimate use (protocol commitments)

**With creation proof:** No change. DATA_RETURN is intentional and bounded.

**Verdict: EXISTING DEFENSE.** 40 bytes per transaction, intentional.

### Attack 9: Multi-input preimage data

**Goal:** Embed data via PREIMAGE fields across multiple inputs.

**Existing defense:** MAX_PREIMAGE_FIELDS_PER_TX = 2 (64 bytes total
across ALL inputs, regardless of input count).

**With creation proof:** No change. This is a spend-side defense.

**Verdict: EXISTING DEFENSE.** 64 bytes per transaction.

### Attack 10: Forge creation proof for someone else's output

**Goal:** Create a valid creation proof that computes to someone else's
MLSC root, allowing the attacker to claim that output.

**Analysis:** The creation proof commits to value_commitment, which binds
the field values and pubkeys. The attacker would need to find a different
set of (templates, value_commitments) that produces the same root. This
requires a collision in the Merkle tree construction — finding two different
sets of leaves with the same root. This is a collision attack on SHA256
(2^128 work). **Infeasible.**

The creation proof does not weaken spending security.

**Verdict: BLOCKED.**

---

## Privacy Analysis

### What is revealed at creation time

| Data | Visible? | Content |
|---|---|---|
| Block types per rung | Yes | SIG, CSV, MULTISIG, CTV, etc. |
| Inverted flags | Yes | Which blocks are negated |
| Coil type | Yes | UNLOCK, UNLOCK_TO, COVENANT |
| Attestation mode | Yes | INLINE, AGGREGATE, DEFERRED |
| Number of rungs | Yes | How many spending paths |
| Field values | No | Hidden in value_commitment |
| Pubkeys | No | Hidden in value_commitment |
| Hash commitments | No | Hidden in value_commitment |
| Timelock values | No | Hidden in value_commitment |

### Privacy assessment

**Revealed:** The structure of spending conditions. An observer can see
"this output has a SIG + CSV path and a MULTISIG backup path." This reveals
the spending POLICY STRUCTURE but not the IDENTITY of participants.

**Hidden:** All pubkeys (via merkle_pub_key folded into value_commitment),
all field values (HASH256, NUMERIC, SCHEME values), all key identities.

**Comparison to existing systems:**

- Current Ladder Script: full privacy (nothing revealed until spend). The
  creation proof reveals structural metadata.
- Taproot key-path: full privacy (looks like any other spend). But
  script-path reveals the script at spend time.
- Taproot script-path: reveals the executed script + all its opcodes.
  Similar level of structural revelation as our creation proof.

**Assessment:** The privacy cost is PARTIAL. Structure visible, identity
hidden. For most use cases, the sensitive information is WHO controls the
funds, not the type of conditions used. The creation proof reveals about
the same information as a Taproot script-path spend — but at creation
time instead of spend time.

### Privacy position

Structure visible, identity hidden. This is the tradeoff for creation-time
validation. It is comparable to the information revealed by a Taproot
script-path spend. No mitigation needed — the sensitive data (keys,
values, identities) remains hidden.

---

## Impact on Existing Systems

### Spending flow

**No change.** The spending witness (LadderWitness + MLSCProof) is
identical. The creation proof is only validated when the creating
transaction is accepted, not when its outputs are spent.

### UTXO set

**No change.** UTXO entries remain: scriptPubKey (0xC2 + 32 root) + value.
The creation proof is in the witness (prunable, not stored in UTXO set).

### MLSC Merkle tree

**Minor change.** The leaf computation uses the same TaggedHash but with
(structural_template || value_commitment) instead of the current
(block_data || pubkeys). The tree construction algorithm (sorted interior
nodes) is unchanged.

### Evaluator

**No change at evaluation time.** The evaluator still receives merged
conditions + witness and evaluates blocks. The creation proof validation
is a separate step during block acceptance.

### Descriptor notation / RPC

**Minor change.** `signladder` and `signrungtx` must generate creation
proof data alongside the transaction. The structural templates and value
commitments are byproducts of the existing conditions-building process —
the node already has this data when constructing the transaction.

### Block validation performance

**Small overhead.** Per MLSC output: deserialize template (~10 bytes),
validate block types (table lookup), compute leaf hash (1 SHA256),
build tree (log2(R) SHA256 operations), compare root (32-byte memcmp).

For a transaction with 2 outputs, 2 rungs: ~6 SHA256 operations.
For a transaction with 100 outputs, 100 rungs: ~200 SHA256 operations.

SHA256 throughput on modern hardware: ~1 GB/s. 200 operations ≈ negligible.

### Pruning

Creation proof data is in the witness. Witness data can be pruned after
block validation (same as SegWit witness). Pruning nodes do not retain
creation proofs. Full archival nodes do.

### Light clients / SPV

Light clients verify block headers, not full transactions. Creation proofs
do not affect SPV verification. Light clients trust that full nodes
validated the creation proofs.

---

## Residual Embeddable Surface (Post Creation Proof)

### At creation time (on-chain)

| Channel | Bytes | Attacker-chosen? |
|---|---|---|
| MLSC root per output | 32 | No — protocol-derived hash output |
| Value commitments (witness) | 32/rung | No — SHA256 output |
| Structural templates (witness) | ~10/rung | No — validated enums |
| Output values | 8/output | No — constrained by dust |
| DATA_RETURN | 40 max | Yes — intentional, bounded |
| nLockTime | 4 | Yes — standard Bitcoin |
| nSequence per input | 4 | Yes — standard Bitcoin |
| Template ordering steganography | ~0.75/rung | Negligible — requires codebook |

**Readable attacker-chosen data at creation: 48 bytes per transaction**
(DATA_RETURN + standard Bitcoin fields). Everything else is either
protocol-derived, hash outputs, or validated structure.

### At spend time (on-chain)

| Channel | Bytes | Attacker-chosen? |
|---|---|---|
| PREIMAGE fields | 64/tx max | Yes — hash-bound |
| Conditions HASH256 values | ~32/block | Yes — revealed in MLSC proof |
| Nonce grinding | ~3/sig | Yes — unfixable |

Spend-side is unchanged from current system.

### Comparison to Taproot

| | Taproot | Ladder + Creation Proof |
|---|---|---|
| Creation readable data | ~400,000 bytes (witness) | 48 bytes |
| UTXO attacker data | 32 bytes/output (unverifiable) | 32 bytes/output (protocol-derived) |
| Spend readable data | ~400,000 bytes (witness) | ~100 bytes |

---

## Implementation Checklist

### serialize.h / serialize.cpp
- [ ] Define CreationProof struct (templates + value_commitments)
- [ ] DeserializeCreationProof function
- [ ] SerializeCreationProof function (for signrungtx/signladder)
- [ ] Validate structural templates (known block types, valid inversion)

### conditions.cpp
- [ ] ComputeCreationLeaf(template, value_commitment) — tagged hash
- [ ] BuildCreationTree(leaves) — same sorted interior node algorithm
- [ ] VerifyCreationProof(outputs, creation_proof) — recompute + compare

### evaluator.cpp
- [ ] Call VerifyCreationProof in ValidateRungOutputs (or new function)
- [ ] Reject v4 transactions with MLSC outputs but no creation proof

### rpc.cpp
- [ ] signrungtx: generate creation proof alongside transaction
- [ ] signladder: generate creation proof alongside transaction
- [ ] decoderungtx: display creation proof data

### serialize format
- [ ] Define wire format for creation proof section in witness
- [ ] Handle DATA_RETURN outputs (no creation proof needed)

### Tests
- [ ] Creation proof validation: valid proofs accepted
- [ ] Creation proof validation: missing proof rejected
- [ ] Creation proof validation: mismatched root rejected
- [ ] Creation proof validation: invalid block type rejected
- [ ] Creation proof validation: invalid inversion rejected
- [ ] Spam test: cannot embed readable data in root
- [ ] Spam test: cannot embed readable data in value_commitment
- [ ] Performance test: creation proof validation overhead
- [ ] Privacy test: value_commitment hides field values
- [ ] Backward compatibility: spending existing outputs unchanged

---

## Open Questions

1. **Leaf computation change:** The current leaf uses
   `TaggedHash("LadderLeaf", rung_serialized_data || pubkeys)`. The
   creation proof leaf uses
   `TaggedHash("LadderLeaf", template || value_commitment)`. These must
   produce the same leaf for the root to match. This requires either:
   (a) changing the leaf computation to use template + commitment, or
   (b) ensuring the serialized rung data decomposes cleanly into template
   + values such that the hash is equivalent.
   Option (a) is cleaner — it changes the leaf format but the tree
   algorithm stays the same.

2. **Witness section placement:** Where exactly does the creation proof
   go in the witness? Options:
   (a) After all input witness stacks, as a new section
   (b) Appended to the last input's witness stack
   (c) In a new transaction field (not witness — loses discount)
   Option (a) is cleanest and matches the "per-transaction" nature of
   creation proofs.

3. **Activation:** The creation proof changes the leaf computation.
   Existing MLSC outputs (created before activation) use the old leaf
   format. Post-activation outputs use the new format. The verifier must
   handle both (check activation height of creating transaction).

4. **Partial privacy improvement:** Could we hide the structural templates
   too, using a ZK proof that the templates are valid? This would restore
   full creation-time privacy. Deferred to future work — the current
   partial privacy is sufficient for v1.

---

*Creation Proof Specification v0.1 · Bitcoin Ghost Project · March 2026*
