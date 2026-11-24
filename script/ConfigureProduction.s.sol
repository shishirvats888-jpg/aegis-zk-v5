// Created & Architected by Shishir Vats | AEGIS-ZK Production Activation Script
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";

contract ConfigureProduction is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address oracleGuardAddr = 0x165e8431B979F8A7d6D993A5727B7D6c6244f6F1;
        address registryAddr = 0x4261E706588479F9e44F3Ba3AdB164fF2257c871;
        address usdcBaseSepolia = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
        address chainlinkUsdcUsdBaseSepolia = 0xd30e2101a97dcbAeBCBC04F14C3f624E67A35165;

        bytes memory sp1PublicValues = vm.envBytes("PUBLIC_VALUES");
        bytes memory sp1ProofBytes = vm.envBytes("PROOF_BYTES");

        vm.startBroadcast(deployerKey);
        AegisSessionRegistry(registryAddr).registerEnclaveSession(sp1PublicValues, sp1ProofBytes);
        AegisOracleGuard(oracleGuardAddr).configureTokenFeed(
            usdcBaseSepolia,
            chainlinkUsdcUsdBaseSepolia,
            address(0),
            3600,
            150
        );
        vm.stopBroadcast();
    }
}
