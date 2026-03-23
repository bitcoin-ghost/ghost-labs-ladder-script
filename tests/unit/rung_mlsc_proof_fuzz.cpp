// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>

#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

/** Fuzz the MLSC proof deserialization and verification.
 *  Feeds random bytes to DeserializeMLSCProof, then if successful,
 *  attempts VerifyMLSCProof with a dummy root.
 *  Must never crash or invoke UB. */
FUZZ_TARGET(rung_mlsc_proof)
{
    if (buffer.size() < 4) return;

    std::vector<uint8_t> data(buffer.begin(), buffer.end());

    // Deserialize proof
    rung::MLSCProof proof;
    std::string error;
    if (!rung::DeserializeMLSCProof(data, proof, error)) {
        assert(!error.empty());
        return;
    }

    // If deserialization succeeded, verify structural invariants
    assert(proof.rung_index < proof.total_rungs || proof.total_rungs == 0);

    // Attempt verification with a dummy root (will fail but must not crash)
    uint256 dummy_root;
    rung::RungCoil dummy_coil;
    std::vector<std::vector<uint8_t>> rung_pks;
    std::vector<std::vector<std::vector<uint8_t>>> relay_pks;
    std::string verify_error;

    rung::VerifyMLSCProof(proof, dummy_coil, dummy_root, rung_pks, relay_pks,
                           verify_error, nullptr, {});

    // Roundtrip: serialize then deserialize
    auto reserialized = rung::SerializeMLSCProof(proof);
    rung::MLSCProof proof2;
    std::string error2;
    bool ok2 = rung::DeserializeMLSCProof(reserialized, proof2, error2);
    if (ok2) {
        assert(proof2.total_rungs == proof.total_rungs);
        assert(proof2.total_relays == proof.total_relays);
        assert(proof2.rung_index == proof.rung_index);
    }
}
