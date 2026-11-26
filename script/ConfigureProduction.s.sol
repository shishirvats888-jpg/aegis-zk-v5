// Created & Architected by Shishir Vats | AEGIS-ZK Production Activation Script
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/AegisSecurityCouncil.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";
import "../src/AegisUnderwritingVault.sol";

contract ConfigureProduction is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address councilAddr = vm.envAddress("SECURITY_COUNCIL_ADDRESS");
        address oracleGuardAddr = vm.envAddress("ORACLE_GUARD_ADDRESS");
        address registryAddr = vm.envAddress("SESSION_REGISTRY_ADDRESS");
        address vaultAddr = vm.envAddress("UNDERWRITING_VAULT_ADDRESS");
        address factoryAddr = vm.envAddress("ACCOUNT_FACTORY_ADDRESS");
        address usdcToken = vm.envAddress("USDC_ADDRESS");
        address chainlinkUsdcUsdFeed = vm.envAddress("USDC_USD_FEED");

        bytes memory sp1PublicValues = vm.envBytes("PUBLIC_VALUES");
        bytes memory sp1ProofBytes = vm.envBytes("PROOF_BYTES");

        bytes memory oracleConfigCalldata = abi.encodeCall(
            AegisOracleGuard.configureTokenFeed,
            (usdcToken, chainlinkUsdcUsdFeed, address(0), 3600, 150)
        );
        bytes memory bindVaultFactoryCalldata = abi.encodeCall(
            AegisUnderwritingVault.setAccountFactory,
            (factoryAddr)
        );

        vm.startBroadcast(deployerKey);

        AegisSessionRegistry(registryAddr).registerEnclaveSession(sp1PublicValues, sp1ProofBytes);

        uint256 oracleActionId = AegisSecurityCouncil(payable(councilAddr)).queueAction(
            oracleGuardAddr,
            0,
            oracleConfigCalldata
        );
        uint256 vaultActionId = AegisSecurityCouncil(payable(councilAddr)).queueAction(
            vaultAddr,
            0,
            bindVaultFactoryCalldata
        );

        vm.stopBroadcast();

        console.log("Enclave Session Registered on AegisSessionRegistry:", registryAddr);
        console.log("Oracle Feed Governance Action Queued ID:", oracleActionId);
        console.log("Vault Factory Binding Action Queued ID:", vaultActionId);
    }
}
