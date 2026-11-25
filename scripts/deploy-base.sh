#!/usr/bin/env bash
set -euo pipefail

: "${RPC_URL:?Set RPC_URL (Base Sepolia or Base Mainnet RPC)}"
: "${PRIVATE_KEY:?Set PRIVATE_KEY}"
: "${ENTRYPOINT_ADDRESS:?Set ENTRYPOINT_ADDRESS (0x0000000071727De22E5E9d8BAf0edAc6f37da032)}"
: "${SP1_VERIFIER_ADDRESS:?Set SP1_VERIFIER_ADDRESS (Succinct SP1 Verifier Gateway)}"
: "${USDC_ADDRESS:?Set USDC_ADDRESS}"
: "${PAYMASTER_ADDRESS:?Set PAYMASTER_ADDRESS}"
: "${SEQUENCER_UPTIME_FEED:?Set SEQUENCER_UPTIME_FEED}"
: "${INITIAL_PCR0:?Set INITIAL_PCR0 from build-and-prove.sh}"
: "${NITRO_VKEY:?Set NITRO_VKEY from build-and-prove.sh}"
: "${GUARDIAN_1:?Set GUARDIAN_1}"
: "${GUARDIAN_2:?Set GUARDIAN_2}"
: "${GUARDIAN_3:?Set GUARDIAN_3}"
: "${GUARDIAN_4:?Set GUARDIAN_4}"
: "${GUARDIAN_5:?Set GUARDIAN_5}"

chmod +x scripts/build-and-prove.sh
forge build
forge test -vvv

forge script script/DeployAegis.s.sol:DeployAegis \
  --rpc-url "$RPC_URL" \
  --broadcast \
  -vvvv
