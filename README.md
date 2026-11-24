> **Created & Architected by Shishir Vats** | Zero-Trust Execution Firewall & Parametric Underwriting for AI Agents

# AEGIS-ZK (v5.2 Zero-Trust Edition)
**Cryptographic Execution Guardrail & Parametric Underwriting Protocol for Autonomous AI Agents**

### 5-Layer Defense-in-Depth Architecture
- **Layer 0 (`AegisSecurityCouncil.sol`):** 3-of-5 Multi-Sig + 48h public Timelock for `PCR0` upgrades + asymmetric instant Pause Guardian.
- **Layer 1 (`AegisOracleGuard.sol`):** `zkTLS` `blockhash(N-1)` freshness + live Chainlink sanity feeds + `wstETH.stEthPerToken()` math + L2 Sequencer uptime checks.
- **Layer 2 (`AegisSessionRegistry.sol` & `sp1-nitro-verifier/`):** AWS Nitro Enclave volatile RAM keys (24h TTL) verified via Succinct SP1 zkVM enforcing strict RFC 8949 canonical CBOR.
- **Layer 3 (`AegisExecutionHook.sol` & `AegisAccountFactory.sol`):** Atomic `nonce == 0` wallet deployment, EIP-1153 transient reentrancy mutex (`_hookLock`), `delegatecall`/self-call ban, USDT force-zero approvals, and 24h rolling outflow velocity caps.
- **Layer 4 (`AegisUnderwritingVault.sol`):** ERC-4626 parametric USDC vault with 20% Operator First-Loss Bond, `encumberedLiquidity` accounting, 72h optimistic dispute window, and 10% hard Epoch Drawdown Cap.

---

### Live Deployment (Base Sepolia Testnet — Chain ID `84532`)
* **Live Interactive Demo:** https://aegis-zk-v5-1qll.vercel.app/
* **3-Minute Live Video Walkthrough:** [Watch Demo Video](https://www.youtube.com/watch?v=_loYx0o4eVw)
* **Author & Architect:** Shishir Vats (Verified on-chain via `PROTOCOL_AUTHOR()`)

| Smart Contract | Live Base Sepolia Address | Explorer |
| :--- | :--- | :--- |
| **AegisSecurityCouncil** | `0xE78947bFfF08E188272D09E4B39Df711c839aC72` | [View on Basescan](https://basescan.org) |
| **AegisOracleGuard** | `0xe2D51995d4236a00E90939F4eEF23b0a85057Fcd` | [View on Basescan](https://basescan.org) |
| **AegisSessionRegistry** | `0xBf477Eb152fE60Ce819fB6f8163d3321d6A83b61` | [View on Basescan](https://basescan.org) |
| **AegisExecutionHook** | `0xe5eF2b78e7587aCf709D1419c5155d40826bc8DA` | [View on Basescan](https://basescan.org) |
| **AegisAccountFactory** | `0x56FBD96Ab8cFA7D39B54aA7791906CCa432111FE` | [View on Basescan](https://basescan.org) |
| **AegisUnderwritingVault** | `0x2BD751037b635C54fDF0F613705BEEaa22125887` | [View on Basescan](https://basescan.org) |
