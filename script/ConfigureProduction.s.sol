// Created & Architected by Shishir Vats | AEGIS-ZK Production Activation Script
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/AegisSecurityCouncil.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";

contract ConfigureProduction is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address councilAddr = 0x0790479Ff081D18D2D19c2E8C0E75d1c03784a72;
        address oracleGuardAddr = 0x165e8431B979F8A7d6D993A5727B7D6c6244f6F1;
        address registryAddr = 0x4261E706588479F9e44F3Ba3AdB164fF2257c871;
        address usdcBaseSepolia = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
        address chainlinkUsdcUsdBaseSepolia = 0xd30e2101a97dcbAeBCBC04F14C3f624E67A35165;

        bytes memory sp1PublicValues = vm.envBytes("PUBLIC_VALUES");
        bytes memory sp1ProofBytes = vm.envBytes("PROOF_BYTES");

        bytes memory oracleConfigCalldata = abi.encodeCall(
            AegisOracleGuard.configureTokenFeed,
            (usdcBaseSepolia, chainlinkUsdcUsdBaseSepolia, address(0), 3600, 150)
        );

        vm.startBroadcast(deployerKey);

        // 1. Register SP1-verified AWS Nitro Enclave session directly on AegisSessionRegistry
        AegisSessionRegistry(registryAddr).registerEnclaveSession(sp1PublicValues, sp1ProofBytes);

        // 2. Queue Chainlink USDC/USD feed activation through AegisSecurityCouncil (48h timelock)
        uint256 actionId = AegisSecurityCouncil(payable(councilAddr)).queueAction(
            oracleGuardAddr,
            0,
            oracleConfigCalldata
        );

        vm.stopBroadcast();

        console.log("Enclave Session Registered on AegisSessionRegistry:", registryAddr);
        console.log("Oracle Feed Governance Action Queued ID:", actionId);
    }
}
