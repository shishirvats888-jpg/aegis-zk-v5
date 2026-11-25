#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Building Reproducible AWS Nitro Enclave EIF & Extracting Full 48-Byte Hardware PCR0 ==="
docker build -t aegis-nitro-enclave:v5.2 ./agent-enclave-runner
nitro-cli build-enclave \
  --docker-uri aegis-nitro-enclave:v5.2 \
  --output-file aegis-nitro-enclave.eif > enclave-measurements.json

RAW_PCR0=$(jq -r '.Measurements.PCR0' enclave-measurements.json)
if [[ ${#RAW_PCR0} -ne 96 || "$RAW_PCR0" == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ]]; then
  echo "FATAL: Failed to extract valid 48-byte (96 hex char) non-zero PCR0 from nitro-cli build-enclave" >&2
  exit 1
fi

INITIAL_PCR0_HIGH="0x${RAW_PCR0:0:64}"
INITIAL_PCR0_LOW="0x${RAW_PCR0:64:32}00000000000000000000000000000000"
echo "INITIAL_PCR0_HIGH=$INITIAL_PCR0_HIGH"
echo "INITIAL_PCR0_LOW=$INITIAL_PCR0_LOW"

echo "=== 2. Compiling SP1 zkVM Guest ELF & Extracting Program Verification Key ==="
(cd sp1-nitro-verifier && cargo prove build)
NITRO_VKEY=$(cd sp1-nitro-verifier/script && PRINT_VKEY_ONLY=true cargo run --release | grep '^NITRO_VKEY=' | cut -d'=' -f2)
if [[ -z "$NITRO_VKEY" ]]; then
  echo "FATAL: Failed to extract NITRO_VKEY from SP1 ELF" >&2
  exit 1
fi
echo "NITRO_VKEY=$NITRO_VKEY"
