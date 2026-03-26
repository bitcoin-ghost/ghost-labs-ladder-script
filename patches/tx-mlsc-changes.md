# TX_MLSC Patch Changes

Additional changes to Bitcoin Core for TX_MLSC (on top of the base
`bitcoin-core-v30-ladder-script.patch`).

## primitives/transaction.h

### CTransaction class
Add after `nLockTime`:
```cpp
const uint256 conditions_root;
const std::vector<uint8_t> creation_proof;
```

### CMutableTransaction struct
Add after `nLockTime`:
```cpp
uint256 conditions_root;
std::vector<uint8_t> creation_proof;
```

### UnserializeTransaction
When flag == 0x02 and version == 4:
1. Read `conditions_root` (32 bytes) after inputs
2. Read value-only outputs (CompactSize count + int64 per output)
3. Inflate each output to CTxOut(value, 0xDF + conditions_root)
4. After per-input witnesses, read creation_proof (CompactSize length + bytes)

### SerializeTransaction
When version == 4 and conditions_root is non-null:
1. Write flag = 0x02
2. Write inputs
3. Write conditions_root (32 bytes)
4. Write value-only outputs (CompactSize count + int64 per output)
5. Write per-input witnesses
6. Write creation_proof (CompactSize length + bytes)

## primitives/transaction.cpp

Update both CTransaction constructors to copy conditions_root and creation_proof
from CMutableTransaction.

Update CMutableTransaction(const CTransaction&) to copy new fields.

## script/solver.cpp

Change prefix check from `0xc1` to `0xdf || 0xc1`:
```cpp
if (scriptPubKey.size() >= 2 && (scriptPubKey[0] == 0xdf || scriptPubKey[0] == 0xc1)) {
```

## addresstype.cpp

Change LadderDestination scriptPubKey reconstruction from `0xc1` to `0xdf`.

## script/interpreter.cpp

No changes beyond existing patch (PrecomputedTransactionData handles
TX_MLSC through the inflated CTxOut, which has the same scriptPubKey
format as standard MLSC).

## src/rung/ (all files)

Synced from labs repo `src/rung/` by `scripts/build.sh`. Contains all
TX_MLSC logic: creation proof validation, TX_MLSC leaf computation,
output_index in coil, createtxmlsc RPC, signladder funding tx lookup.

Prefix constant: `RUNG_MLSC_PREFIX = 0xDF` (was 0xC2).
