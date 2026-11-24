// Created & Architected by Shishir Vats | AEGIS-ZK Certora Formal Spec
// Certora CVL Formal Verification Specification for AEGIS-ZK v5.2
methods {
    function totalLpAssets() external returns (uint256) envfree;
    function protocolReserve() external returns (uint256) envfree;
    function encumberedLiquidity() external returns (uint256) envfree;
    function availableTVL() external returns (uint256) envfree;
}

// Invariant 1: Encumbered Liquidity Solvency (Vault gross assets always >= encumbered claims)
invariant inv_EncumberedSolvency()
    totalLpAssets() + protocolReserve() >= encumberedLiquidity();

// Invariant 2: Available TVL Exact Conservation
invariant inv_AvailableTVLConservation()
    availableTVL() == (totalLpAssets() + protocolReserve()) - encumberedLiquidity();
