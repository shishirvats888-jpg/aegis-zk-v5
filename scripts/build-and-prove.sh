#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Building Reproducible AWS Nitro Enclave EIF & Extracting Hardware PCR0 ==="
docker build -t aegis-nitro-enclave:v5.2 ./agent-enclave-runner
nitro-cli build-enclave \
  --docker-uri aegis-nitro-enclave:v5.2 \
  --output-file aegis-nitro-enclave.eif > enclave-measurements.json

INITIAL_PCR0="0x$(jq -r '.Measurements.PCR0' enclave-measurements.json)"
if [[ "$INITIAL_PCR0" == "0x" || "$INITIAL_PCR0" == "0xnull" ]]; then
  echo "FATAL: Failed to extract real PCR0 from nitro-cli build-enclave" >&2
  exit 1
fi
echo "INITIAL_PCR0=$INITIAL_PCR0"

echo "=== 2. Compiling SP1 zkVM Guest ELF & Extracting Program Verification Key ==="
(cd sp1-nitro-verifier && cargo prove build)
NITRO_VKEY=$(cd sp1-nitro-verifier/script && PRINT_VKEY_ONLY=true cargo run --release | grep '^NITRO_VKEY=' | cut -d'=' -f2)
if [[ -z "$NITRO_VKEY" ]]; then
  echo "FATAL: Failed to extract NITRO_VKEY from SP1 ELF" >&2
  exit 1
fi
echo "NITRO_VKEY=$NITRO_VKEY"
