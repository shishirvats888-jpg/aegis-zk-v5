// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/AegisSecurityCouncil.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";
import "../src/AegisExecutionHook.sol";
import "../src/AegisAccountFactory.sol";
import "../src/AegisUnderwritingVault.sol";

contract DeployAegis is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        address entryPoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        address sp1Gateway = vm.envAddress("SP1_VERIFIER_ADDRESS");
        address usdcToken = vm.envAddress("USDC_ADDRESS");
        address paymaster = vm.envAddress("PAYMASTER_ADDRESS");
        address sequencerUptimeFeed = vm.envAddress("SEQUENCER_UPTIME_FEED");

        bytes32 initialPCR0 = vm.envBytes32("INITIAL_PCR0");
        bytes32 nitroVKey = vm.envBytes32("NITRO_VKEY");
        require(initialPCR0 != bytes32(0), "AEGIS: non-zero INITIAL_PCR0 required");
        require(nitroVKey != bytes32(0), "AEGIS: non-zero NITRO_VKEY required");

        address[5] memory guardians = [
            vm.envAddress("GUARDIAN_1"),
            vm.envAddress("GUARDIAN_2"),
            vm.envAddress("GUARDIAN_3"),
            vm.envAddress("GUARDIAN_4"),
            vm.envAddress("GUARDIAN_5")
        ];

        vm.startBroadcast(deployerKey);

        AegisSecurityCouncil council = new AegisSecurityCouncil(guardians);
        AegisOracleGuard oracleGuard = new AegisOracleGuard(address(council), sequencerUptimeFeed);
        AegisSessionRegistry registry = new AegisSessionRegistry(
            sp1Gateway,
            nitroVKey,
            initialPCR0,
            address(council),
            address(council)
        );

        address[] memory canonicalTokens = new address[](1);
        canonicalTokens = usdcToken;

        AegisExecutionHook hook = new AegisExecutionHook(
            address(registry),
            entryPoint,
            address(council),
            paymaster,
            address(council),
            100 gwei,
            canonicalTokens
        );
        AegisAccountFactory factory = new AegisAccountFactory(
            address(hook),
            entryPoint,
            address(council),
            deployer,
            0.001 ether
        );
        AegisUnderwritingVault vault = new AegisUnderwritingVault(
            usdcToken,
            address(council),
            address(council)
        );

        vm.stopBroadcast();

        console.log("AegisSecurityCouncil:", address(council));
        console.log("AegisOracleGuard:", address(oracleGuard));
        console.log("AegisSessionRegistry:", address(registry));
        console.log("AegisExecutionHook:", address(hook));
        console.log("AegisAccountFactory:", address(factory));
        console.log("AegisUnderwritingVault:", address(vault));
    }
}
