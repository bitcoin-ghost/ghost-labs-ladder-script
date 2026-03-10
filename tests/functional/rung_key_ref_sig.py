#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""KEY_REF_SIG block type functional tests."""

import hashlib
from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


def make_keypair():
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


def numeric_hex(val):
    return val.to_bytes(4, 'little').hex()


class KeyRefSigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Mining initial blocks for maturity...")
        self.generate(node, 101)
        self.generatetoaddress(node, 200, self.wallet.get_address())
        self.wallet.rescan_utxos()

        self.test_key_ref_sig_spend(node)
        self.test_key_ref_sig_multi_rung(node)
        self.test_key_ref_sig_negative_wrong_key(node)

    def bootstrap_v4_output_with_relays(self, node, conditions, relays, output_amount=None):
        """Create and confirm a v4 output with conditions + relays."""
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        if output_amount is None:
            output_amount = Decimal(input_amount) - Decimal("0.001")

        boot_wif, boot_pubkey = make_keypair()
        outputs = [{"amount": output_amount, "conditions": conditions}]

        change = Decimal(input_amount) - output_amount - Decimal("0.001")
        if change > Decimal("0.01"):
            change_wif, change_pubkey = make_keypair()
            outputs.append({"amount": change, "conditions": [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": change_pubkey}
            ]}]}]})

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            outputs,
            0,
            relays,
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        return txid, 0, output_amount, spk

    def test_key_ref_sig_spend(self, node):
        """KEY_REF_SIG: sign using key commitment from a relay block."""
        self.log.info("Test 1: KEY_REF_SIG basic spend...")

        privkey_wif, pubkey_hex = make_keypair()
        pubkey_commit = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()

        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY_COMMIT", "hex": pubkey_commit},
                {"type": "SCHEME", "hex": "01"},
            ]
        }]}]

        conditions = [{
            "blocks": [{
                "type": "KEY_REF_SIG",
                "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                ]
            }],
            "relay_refs": [0],
        }]

        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": dest_pubkey}
                ]}]
            }]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": privkey_wif}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": privkey_wif}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"], "KEY_REF_SIG spend should be fully signed"

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  PASSED: KEY_REF_SIG spend confirmed!")

    def test_key_ref_sig_multi_rung(self, node):
        """KEY_REF_SIG: two rungs, one using relay ref, one using direct SIG (OR)."""
        self.log.info("Test 2: KEY_REF_SIG multi-rung (OR logic)...")

        privkey_wif1, pubkey_hex1 = make_keypair()
        privkey_wif2, pubkey_hex2 = make_keypair()

        pubkey_commit1 = hashlib.sha256(bytes.fromhex(pubkey_hex1)).hexdigest()
        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY_COMMIT", "hex": pubkey_commit1},
                {"type": "SCHEME", "hex": "01"},
            ]
        }]}]

        conditions = [
            {
                "blocks": [{
                    "type": "KEY_REF_SIG",
                    "fields": [
                        {"type": "NUMERIC", "hex": numeric_hex(0)},
                        {"type": "NUMERIC", "hex": numeric_hex(0)},
                    ]
                }],
                "relay_refs": [0],
            },
            {
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex2}
                ]}],
            },
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": dest_pubkey}
                ]}]
            }]}]
        )

        # Spend via rung 0 (KEY_REF_SIG)
        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": privkey_wif1}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": privkey_wif1}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  PASSED: KEY_REF_SIG multi-rung spend via rung 0!")

    def test_key_ref_sig_negative_wrong_key(self, node):
        """KEY_REF_SIG: wrong key fails (commitment mismatch)."""
        self.log.info("Test 3: KEY_REF_SIG negative (wrong key)...")

        privkey_wif, pubkey_hex = make_keypair()
        wrong_wif, wrong_pubkey = make_keypair()

        pubkey_commit = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()

        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY_COMMIT", "hex": pubkey_commit},
                {"type": "SCHEME", "hex": "01"},
            ]
        }]}]

        conditions = [{
            "blocks": [{
                "type": "KEY_REF_SIG",
                "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                ]
            }],
            "relay_refs": [0],
        }]

        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": dest_pubkey}
                ]}]
            }]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": wrong_wif}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": wrong_wif}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  PASSED: KEY_REF_SIG wrong key rejected!")


if __name__ == '__main__':
    KeyRefSigTest(__file__).main()
