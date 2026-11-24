// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

        // Default Base Sepolia Canonical EntryPoint v0.7 & Succinct SP1 Verifier Gateway
        address entryPoint = vm.envOr("ENTRYPOINT_ADDRESS", address(0x0000000071727De22E5E9d8BAf0edAc6f37da032));
        address sp1Gateway = vm.envOr("SP1_VERIFIER_ADDRESS", address(0x3B6041173B80E77f038f3F2C0f9744f04837185e));
        address usdcToken = vm.envOr("USDC_ADDRESS", address(0x036CbD53842c5426634e7929541eC2318f3dCF7e));
        address paymaster = vm.envOr("PAYMASTER_ADDRESS", deployer);

        bytes32 initialPCR0 = keccak256("AEGIS_NITRO_ENCLAVE_IMAGE_V5_2");
        bytes32 nitroVKey = keccak256("AEGIS_SP1_NITRO_VKEY_V5_2");

        address[5] memory guardians = [
            deployer,
            address(0x1000000000000000000000000000000000000002),
            address(0x1000000000000000000000000000000000000003),
            address(0x1000000000000000000000000000000000000004),
            address(0x1000000000000000000000000000000000000005)
        ];

        vm.startBroadcast(deployerKey);

        AegisSecurityCouncil council = new AegisSecurityCouncil(guardians);
        AegisOracleGuard oracleGuard = new AegisOracleGuard(address(council), address(0));
        AegisSessionRegistry registry = new AegisSessionRegistry(sp1Gateway, nitroVKey, initialPCR0, address(council), address(council));

        address[] memory canonicalTokens = new address[](1);
        canonicalTokens[0] = usdcToken;

        AegisExecutionHook hook = new AegisExecutionHook(
            address(registry), entryPoint, address(council), paymaster, address(council), 100 gwei, canonicalTokens
        );
        AegisAccountFactory factory = new AegisAccountFactory(address(hook), entryPoint, address(council), deployer, 0.001 ether);
        AegisUnderwritingVault vault = new AegisUnderwritingVault(usdcToken, address(council), address(council));

        vm.stopBroadcast();

        console.log("AegisSecurityCouncil:", address(council));
        console.log("AegisOracleGuard:", address(oracleGuard));
        console.log("AegisSessionRegistry:", address(registry));
        console.log("AegisExecutionHook:", address(hook));
        console.log("AegisAccountFactory:", address(factory));
        console.log("AegisUnderwritingVault:", address(vault));
    }
}
