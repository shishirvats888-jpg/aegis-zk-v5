# AEGIS-ZK Security Policy & Live Red-Team War-Game

## Formal Security Invariants
1. **Hardware Root of Trust (`AegisSessionRegistry` + `sp1-nitro-verifier`):** Every enclave signer must be backed by a genuine AWS Nitro `/dev/nsm` COSE_Sign1 P-384 attestation verified in Succinct SP1 up to the AWS Nitro Root-G1 CA, with full 48-byte SHA-384 `PCR0 != 0` and chain/registry `user_data` binding.
2. **Cryptographic Calldata & Nonce Binding (`AegisExecutionHook` + `AegisProtectedSmartAccount`):** Every transaction verifies `keccak256(abi.encodePacked(target, value, callData))` and the smart account's monotonic `nonce` against the enclave's signature.
3. **Post-Execution Balance & Allowance Conservation (`postCheck`):** Outflows cannot exceed the enclave-signed cap or 24-hour rolling velocity cap (`dailyOutflowCap`), and post-execution token allowances for guarded spenders must equal `0`.

## Live Mainnet Red-Team Challenge
- **Funded War-Game Smart Account:** Deployed via `scripts/setup-wargame.sh` on Base Mainnet (`8453`) with real USDC and strict per-tx (`$100`) and 24-hour rolling (`$500`) velocity caps.
- **Rules of Engagement:** Prompt-injection, recipient substitution, signature replay, and approval-drain attempts against the war-game account are explicitly authorized. DoS attacks against RPC infrastructure are out of scope.
