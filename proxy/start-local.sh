#!/bin/bash
# Start the local Ladder Script regtest node + proxy
# Usage: ./start-local.sh [stop]

GHOSTD="/home/defenwycke/dev/projects/ghost-ladder-build/ghost-core/build/bin/ghostd"
GCLI="/home/defenwycke/dev/projects/ghost-ladder-build/ghost-core/build/bin/ghost-cli"
DATADIR="/home/defenwycke/.ghost/ladder-regtest"
PROXY_DIR="$(cd "$(dirname "$0")" && pwd)"
WALLET="ladder"

if [ "$1" = "stop" ]; then
    echo "Stopping proxy..."
    pkill -f "ladder_proxy.py" 2>/dev/null
    echo "Stopping ghostd..."
    $GCLI -datadir="$DATADIR" stop 2>/dev/null
    echo "Done."
    exit 0
fi

# Start ghostd if not running
if ! $GCLI -datadir="$DATADIR" getblockchaininfo > /dev/null 2>&1; then
    echo "Starting ghostd (regtest)..."
    $GHOSTD -datadir="$DATADIR" -daemon
    sleep 3
fi

# Load wallet if needed
if ! $GCLI -datadir="$DATADIR" -rpcwallet="$WALLET" getwalletinfo > /dev/null 2>&1; then
    echo "Loading wallet '$WALLET'..."
    $GCLI -datadir="$DATADIR" loadwallet "$WALLET" 2>/dev/null || \
    $GCLI -datadir="$DATADIR" createwallet "$WALLET" 2>/dev/null
fi

# Mine initial blocks if chain is short
BLOCKS=$($GCLI -datadir="$DATADIR" getblockcount 2>/dev/null)
if [ "$BLOCKS" -lt 150 ]; then
    ADDR=$($GCLI -datadir="$DATADIR" -rpcwallet="$WALLET" getnewaddress "" bech32)
    NEED=$((150 - BLOCKS))
    echo "Mining $NEED blocks to reach maturity..."
    $GCLI -datadir="$DATADIR" generatetoaddress "$NEED" "$ADDR" > /dev/null
fi

echo "Chain: $($GCLI -datadir="$DATADIR" getblockcount) blocks"
echo "Balance: $($GCLI -datadir="$DATADIR" -rpcwallet="$WALLET" getbalance) BTC"

# Start proxy if not running
if ! curl -s http://localhost:8801/api/ladder/status > /dev/null 2>&1; then
    echo "Starting proxy on port 8801..."
    cd "$PROXY_DIR" && python3 ladder_proxy.py > /tmp/ladder-proxy.log 2>&1 &
    sleep 2
fi

echo ""
echo "Ready! Proxy at http://localhost:8801"
echo "Engine signet tab will auto-detect localhost."
echo ""
echo "Stop with: $0 stop"
