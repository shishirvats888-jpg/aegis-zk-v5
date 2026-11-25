#!/usr/bin/env bash
set -euo pipefail

: "${RPC_URL:?Set RPC_URL (Base Sepolia or Base Mainnet)}"
: "${PRIVATE_KEY:?Set PRIVATE_KEY}"
: "${FACTORY_ADDRESS:?Set FACTORY_ADDRESS}"
: "${HOOK_ADDRESS:?Set HOOK_ADDRESS}"
: "${USDC_ADDRESS:?Set USDC_ADDRESS}"

OWNER_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")
SALT=$(cast keccak "AEGIS_WARGAME_V5_2_$(date +%s)")

echo "=== 1. Deploying Guarded War-Game Smart Account ==="
cast send "$FACTORY_ADDRESS" \
  "createProtectedAccount(address,bytes32)" \
  "$OWNER_ADDR" "$SALT" \
  --value 0.001ether \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY"

echo "=== 2. Configure Strict $500/day Rolling USDC Velocity Cap on Hook ==="
echo "Call setDailyOutflowCap(<SMART_ACCOUNT>, $USDC_ADDRESS, 500000000) from your Safe/Council or Smart Account."
