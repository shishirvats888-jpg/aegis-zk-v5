# AEGIS-ZK (v5.2 Zero-Trust Edition)
**Cryptographic Execution Guardrail & Parametric Underwriting Protocol for Autonomous AI Agents**

### 5-Layer Defense-in-Depth Architecture
- **Layer 0 (`AegisSecurityCouncil.sol`):** 3-of-5 Multi-Sig + 48h public Timelock for `PCR0` upgrades + asymmetric instant Pause Guardian.
- **Layer 1 (`AegisOracleGuard.sol`):** `zkTLS` `blockhash(N-1)` freshness + live Chainlink sanity feeds + `wstETH.stEthPerToken()` math + L2 Sequencer uptime checks.
- **Layer 2 (`AegisSessionRegistry.sol` & `sp1-nitro-verifier/`):** AWS Nitro Enclave volatile RAM keys (24h TTL) verified via Succinct SP1 zkVM enforcing strict RFC 8949 canonical CBOR.
- **Layer 3 (`AegisExecutionHook.sol` & `AegisAccountFactory.sol`):** Atomic `nonce == 0` wallet deployment, EIP-1153 transient reentrancy mutex (`_hookLock`), `delegatecall`/self-call ban, USDT force-zero approvals, and 24h rolling outflow velocity caps.
- **Layer 4 (`AegisUnderwritingVault.sol`):** ERC-4626 parametric USDC vault with 20% Operator First-Loss Bond, `encumberedLiquidity` accounting, 72h optimistic dispute window, and 10% hard Epoch Drawdown Cap.
