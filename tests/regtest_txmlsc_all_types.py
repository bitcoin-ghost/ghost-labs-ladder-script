#!/usr/bin/env python3
"""Test the 17 remaining block types with corrected field types."""
import json, base64, urllib.request, sys

PUBKEY = "03d54cd37930b0c5587333d55bf4841843a922a5af7546818ba8ac2c5cfa2cf93d"
PREIMAGE = "aa" * 32  # dummy 32-byte preimage
ZERO_HASH = "0" * 64

def rpc(method, params):
    data = json.dumps({"jsonrpc":"1.0","id":"t","method":method,"params":params}).encode()
    req = urllib.request.Request("http://127.0.0.1:18443/wallet/test", data=data, headers={"Content-Type":"text/plain"})
    req.add_header("Authorization","Basic "+base64.b64encode(b"test:test").decode())
    try: return json.loads(urllib.request.urlopen(req,timeout=30).read())
    except urllib.request.HTTPError as e: return json.loads(e.read())
    except Exception as e: return {"error":{"message":str(e)}}

def get_utxo():
    for u in rpc("listunspent",[1,9999])["result"]:
        if u["amount"]>=1 and u["spendable"]: return u["txid"],u["vout"],u["amount"]

def mine():
    rpc("generatetoaddress",[1,rpc("getnewaddress",[])["result"]])

def fund(rungs, amounts):
    txid,vout,amt = get_utxo()
    change = round(amt-sum(amounts)-0.001,8)
    all_a = amounts+[change]
    cr = {"output_index":len(amounts),"blocks":[{"type":"SIG","fields":[{"type":"SCHEME","hex":"01"}]}],"pubkeys":[PUBKEY]}
    r = rpc("createtxmlsc",[[{"txid":txid,"vout":vout}],all_a,rungs+[cr]])
    if r.get("error"): return None,r["error"]["message"]
    r2 = rpc("signrawtransactionwithwallet",[r["result"]["hex"]])
    r3 = rpc("sendrawtransaction",[r2["result"]["hex"]])
    if r3.get("error"): return None,r3["error"]["message"]
    mine()
    return r3["result"],None

S = "01"
passed=failed=0
errors=[]

TESTS = [
    # Blocks that need PREIMAGE instead of HASH256
    ("HASH_GUARDED", [{"output_index":0,"blocks":[{"type":"HASH_GUARDED","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE}]}]}], [0.1]),

    ("ANCHOR_POOL", [{"output_index":0,"blocks":[{"type":"ANCHOR_POOL","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"0a"},
        {"type":"NUMERIC","hex":"e8030000"}]}],"pubkeys":[PUBKEY]}], [0.1]),

    ("ANCHOR_RESERVE", [{"output_index":0,"blocks":[{"type":"ANCHOR_RESERVE","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"01"},
        {"type":"NUMERIC","hex":"03"},
        {"type":"NUMERIC","hex":"02"},
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"e8030000"}]}]}], [0.1]),

    ("ANCHOR_SEAL", [{"output_index":0,"blocks":[{"type":"ANCHOR_SEAL","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"01"}]}]}], [0.1]),

    ("TIMER_CONTINUOUS", [{"output_index":0,"blocks":[{"type":"TIMER_CONTINUOUS","fields":[
        {"type":"NUMERIC","hex":"90"},
        {"type":"PREIMAGE","hex":PREIMAGE}]}]}], [0.1]),

    ("TIMER_OFF_DELAY", [{"output_index":0,"blocks":[{"type":"TIMER_OFF_DELAY","fields":[
        {"type":"NUMERIC","hex":"90"},
        {"type":"PREIMAGE","hex":PREIMAGE}]}]}], [0.1]),

    ("COUNTER_PRESET", [{"output_index":0,"blocks":[{"type":"COUNTER_PRESET","fields":[
        {"type":"NUMERIC","hex":"03"},
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"90"}]}]}], [0.1]),

    ("COMPARE", [{"output_index":0,"blocks":[{"type":"COMPARE","fields":[
        {"type":"NUMERIC","hex":"03"},  # operator as NUMERIC not SCHEME
        {"type":"NUMERIC","hex":"e803"},
        {"type":"NUMERIC","hex":"10270000"}]}]}], [0.1]),

    ("SEQUENCER", [{"output_index":0,"blocks":[{"type":"SEQUENCER","fields":[
        {"type":"NUMERIC","hex":"01"},
        {"type":"NUMERIC","hex":"05"},
        {"type":"PREIMAGE","hex":PREIMAGE}]}]}], [0.1]),

    ("ONE_SHOT", [{"output_index":0,"blocks":[{"type":"ONE_SHOT","fields":[
        {"type":"NUMERIC","hex":"90"},
        {"type":"PREIMAGE","hex":PREIMAGE}]}]}], [0.1]),

    ("HTLC", [{"output_index":0,"blocks":[{"type":"HTLC","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"NUMERIC","hex":"90"},
        {"type":"SCHEME","hex":S}]}],"pubkeys":[PUBKEY,PUBKEY]}], [0.1]),

    ("HASH_SIG", [{"output_index":0,"blocks":[{"type":"HASH_SIG","fields":[
        {"type":"PREIMAGE","hex":PREIMAGE},
        {"type":"SCHEME","hex":S}]}],"pubkeys":[PUBKEY]}], [0.1]),

    # Legacy blocks that need PUBKEY instead of HASH160
    ("P2PKH_LEGACY", [{"output_index":0,"blocks":[{"type":"P2PKH_LEGACY","fields":[
        {"type":"SCHEME","hex":S}]}],"pubkeys":[PUBKEY]}], [0.1]),

    ("P2WPKH_LEGACY", [{"output_index":0,"blocks":[{"type":"P2WPKH_LEGACY","fields":[
        {"type":"SCHEME","hex":S}]}],"pubkeys":[PUBKEY]}], [0.1]),

    # Legacy blocks that need PREIMAGE instead of HASH
    ("P2SH_LEGACY", [{"output_index":0,"blocks":[{"type":"P2SH_LEGACY","fields":[
        {"type":"PREIMAGE","hex":"0101" + S}]}]}], [0.1]),  # tiny inner conditions

    ("P2WSH_LEGACY", [{"output_index":0,"blocks":[{"type":"P2WSH_LEGACY","fields":[
        {"type":"PREIMAGE","hex":"0101" + S}]}]}], [0.1]),

    ("P2TR_SCRIPT_LEGACY", [{"output_index":0,"blocks":[{"type":"P2TR_SCRIPT_LEGACY","fields":[
        {"type":"PREIMAGE","hex":"0101" + S}]}]}], [0.1]),
]

print(f"=== Testing {len(TESTS)} corrected block types ===\n")
for name,rungs,amounts in TESTS:
    txid,err = fund(rungs,amounts)
    if txid:
        passed+=1; print(f"  PASS: {name}")
    else:
        failed+=1; errors.append((name,err)); print(f"  FAIL: {name} — {err[:120]}")

print(f"\n=== {passed}/{passed+failed} passed, {failed} failed ===")
if errors:
    for n,e in errors: print(f"  {n}: {e[:150]}")
sys.exit(0 if failed==0 else 1)
