// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>
#include <primitives/transaction.h>
#include <hash.h>

#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

/** Fuzz the sighash computation: deserialize conditions from fuzz input,
 *  build a minimal transaction, compute SignatureHashLadder.
 *  Must never crash or invoke UB. */
FUZZ_TARGET(rung_sighash)
{
    if (buffer.size() < 2) return;

    // Deserialize as ladder witness (conditions format)
    std::vector<uint8_t> data(buffer.begin(), buffer.end());
    rung::LadderWitness ladder;
    std::string error;
    if (!rung::DeserializeLadderWitness(data, ladder, error,
                                         rung::SerializationContext::CONDITIONS)) {
        return;
    }

    // Build conditions from deserialized ladder
    rung::RungConditions conditions;
    conditions.rungs = ladder.rungs;
    conditions.relays = ladder.relays;
    conditions.coil = ladder.coil;

    // Build a minimal transaction
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    mtx.vin.emplace_back();
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.emplace_back();
    mtx.vout[0].nValue = 50000;
    // Set a plausible MLSC scriptPubKey on the spent output
    std::vector<uint8_t> mlsc_spk = {0xC2};
    mlsc_spk.resize(33, 0); // 0xC2 + 32 zero bytes

    CTxOut spent_output;
    spent_output.nValue = 100000;
    spent_output.scriptPubKey = CScript(mlsc_spk.begin(), mlsc_spk.end());

    // Precompute transaction data
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, {spent_output});

    // Compute sighash with various hash types — must not crash
    for (uint8_t hashtype : {0x00, 0x01, 0x02, 0x03, 0x40, 0x81, 0xC0}) {
        uint256 sighash;
        rung::SignatureHashLadder(txdata, mtx, 0, hashtype, conditions, sighash);
    }
}
