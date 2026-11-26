#!/usr/bin/env bash
set -euo pipefail

: "${RPC_URL:?Must set RPC_URL (e.g. Base Sepolia or Base Mainnet RPC)}"
: "${ENCLAVE_LOCAL_URL:=http://127.0.0.1:5000}"
: "${SESSION_REGISTRY_ADDRESS:?Must set SESSION_REGISTRY_ADDRESS}"
: "${PRIVATE_KEY:?Must set PRIVATE_KEY}"
: "${NETWORK_PRIVATE_KEY:?Must set NETWORK_PRIVATE_KEY}"

HEADERS=()
[ -n "${REDTEAM_ACCESS_CODE:-}" ] && HEADERS=(-H "x-aegis-access-code: ${REDTEAM_ACCESS_CODE}")

ATTEST_JSON=$(curl -fsSL "${HEADERS[@]}" "${ENCLAVE_LOCAL_URL}/attestation")
ENCLAVE_PUBKEY=$(python3 -c 'import sys, json; print(json.loads(sys.stdin.read())["enclaveSigner"])' <<< "$ATTEST_JSON")
CHAIN_ID=$(python3 -c 'import sys, json; print(json.loads(sys.stdin.read())["chainId"])' <<< "$ATTEST_JSON")
COSE_HEX=$(python3 -c 'import sys, json; print(json.loads(sys.stdin.read())["coseAttestationHex"][2:])' <<< "$ATTEST_JSON")

python3 -c "import pathlib; pathlib.Path('/tmp/aegis_attest.cbor').write_bytes(bytes.fromhex('$COSE_HEX'))"

PROVE_OUT=$(cd sp1-nitro-verifier/script && SP1_PROVER="network" NETWORK_PRIVATE_KEY="$NETWORK_PRIVATE_KEY" \
  NITRO_ATTESTATION_PATH=/tmp/aegis_attest.cbor ENCLAVE_PUBKEY="$ENCLAVE_PUBKEY" \
  BOUND_CHAIN_ID="$CHAIN_ID" BOUND_REGISTRY_ADDRESS="$SESSION_REGISTRY_ADDRESS" \
  cargo run --release)

PUBLIC_VALUES=$(printf '%s\n' "$PROVE_OUT" | awk -F= '/^PUBLIC_VALUES=/{print $2}')
PROOF_BYTES=$(printf '%s\n' "$PROVE_OUT" | awk -F= '/^PROOF_BYTES=/{print $2}')

cast send "$SESSION_REGISTRY_ADDRESS" "registerEnclaveSession(bytes,bytes)" "$PUBLIC_VALUES" "$PROOF_BYTES" \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
echo "REGISTERED_ENCLAVE_SIGNER=$ENCLAVE_PUBKEY"
