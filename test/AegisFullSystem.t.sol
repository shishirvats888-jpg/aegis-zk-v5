// Created & Architected by Shishir Vats | AEGIS-ZK Hardened Adversarial & Symbolic Test Suite
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/AegisSecurityCouncil.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";
import "../src/AegisExecutionHook.sol";
import "../src/AegisAccountFactory.sol";
import "../src/AegisUnderwritingVault.sol";

contract TestERC20 {
    string public name = "USD Coin";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "ERC20: insufficient allowance");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TestAggregatorV3 {
    uint8 public decimals;
    int256 public answer;
    uint256 public startedAt;
    uint256 public updatedAt;

    constructor(uint8 _decimals, int256 _answer) {
        decimals = _decimals;
        answer = _answer;
        startedAt = block.timestamp - 2 hours;
        updatedAt = block.timestamp;
    }

    function setRound(int256 _answer, uint256 _startedAt, uint256 _updatedAt) external {
        answer = _answer;
        startedAt = _startedAt;
        updatedAt = _updatedAt;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, startedAt, updatedAt, 1);
    }
}

contract TestSP1VerifierGateway {
    bytes32 public expectedVKey;
    bool public shouldPass = true;

    constructor(bytes32 _vkey) {
        expectedVKey = _vkey;
    }

    function verifyProof(bytes32 programVKey, bytes calldata, bytes calldata) external view {
        require(shouldPass && programVKey == expectedVKey, "SP1: invalid proof");
    }
}

contract TestEntryPoint {
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }
}

contract TestDexRouter {
    function pullExact(address token, address from, address recipient, uint256 amount) external {
        require(TestERC20(token).transferFrom(from, recipient, amount), "Router: pull failed");
    }
}

contract AegisFullSystemTest is Test {
    AegisSecurityCouncil council;
    AegisOracleGuard oracleGuard;
    AegisSessionRegistry registry;
    AegisExecutionHook hook;
    AegisAccountFactory factory;
    AegisUnderwritingVault vault;

    TestERC20 usdc;
    TestAggregatorV3 sequencerFeed;
    TestAggregatorV3 usdcUsdFeed;
    TestSP1VerifierGateway sp1Gateway;
    TestEntryPoint entryPoint;
    TestDexRouter router;

    uint256 guardian1Pk = 0xA11CE1;
    uint256 guardian2Pk = 0xA11CE2;
    uint256 guardian3Pk = 0xA11CE3;
    uint256 guardian4Pk = 0xA11CE4;
    uint256 guardian5Pk = 0xA11CE5;

    uint256 ownerPk = 0xB0B01;
    uint256 enclavePk = 0xE11C1A;

    address owner;
    address enclaveSigner;
    bytes32 approvedPCR0High = keccak256("PROD_ENCLAVE_EIF_PCR0_HIGH_32_BYTES");
    bytes16 approvedPCR0Low = bytes16(keccak256("PROD_ENCLAVE_EIF_PCR0_LOW_16_BYTES"));
    bytes32 nitroVKey = keccak256("PROD_SP1_NITRO_PROGRAM_VKEY");

    function setUp() public {
        vm.warp(1_735_000_000);
        owner = vm.addr(ownerPk);
        enclaveSigner = vm.addr(enclavePk);

        address[5] memory guardians = [
            vm.addr(guardian1Pk),
            vm.addr(guardian2Pk),
            vm.addr(guardian3Pk),
            vm.addr(guardian4Pk),
            vm.addr(guardian5Pk)
        ];

        usdc = new TestERC20();
        sequencerFeed = new TestAggregatorV3(0, 0);
        usdcUsdFeed = new TestAggregatorV3(8, 100_000_000);
        sp1Gateway = new TestSP1VerifierGateway(nitroVKey);
        entryPoint = new TestEntryPoint();
        router = new TestDexRouter();

        council = new AegisSecurityCouncil(guardians);
        oracleGuard = new AegisOracleGuard(address(council), address(sequencerFeed));
        registry = new AegisSessionRegistry(
            address(sp1Gateway),
            nitroVKey,
            approvedPCR0High,
            approvedPCR0Low,
            address(council),
            address(council)
        );

        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        hook = new AegisExecutionHook(
            address(registry),
            address(entryPoint),
            address(council),
            vm.addr(guardian1Pk),
            address(council),
            100 gwei,
            tokens
        );
        factory = new AegisAccountFactory(
            address(hook),
            address(entryPoint),
            address(council),
            vm.addr(guardian1Pk),
            0.001 ether
        );
        vault = new AegisUnderwritingVault(address(usdc), address(council), address(council));

        _registerTestEnclaveSession();
    }
    function _registerTestEnclaveSession() internal {
        bytes memory pubValues = abi.encode(
            enclaveSigner,
            approvedPCR0High,
            approvedPCR0Low,
            keccak256("CERT_SERIAL_001"),
            uint64(block.timestamp - 30),
            uint64(block.timestamp - 1 days),
            uint64(block.timestamp + 1 days),
            block.chainid,
            address(registry)
        );
        registry.registerEnclaveSession(pubValues, hex"deadbeef");
    }

    function _signEnvelope(
        address account,
        uint256 accountNonce,
        bytes memory executionCalldata,
        uint256 validUntilBlock,
        uint256 maxUsdcOutflow,
        address[] memory spendersZero
    ) internal view returns (bytes memory hookEnvelope) {
        bytes32 mode = bytes32(0);
        uint256[] memory maxTokens = new uint256[](1);
        maxTokens[0] = maxUsdcOutflow;

        bytes32 coreHash = keccak256(
            abi.encode(mode, executionCalldata, validUntilBlock, uint256(0), maxTokens, spendersZero)
        );
        bytes32 maxOutflowHash = keccak256(abi.encode(maxTokens));
        bytes32 rawDigest = keccak256(
            abi.encode(coreHash, block.chainid, account, accountNonce, validUntilBlock, maxOutflowHash)
        );
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rawDigest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(enclavePk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);

        hookEnvelope = abi.encode(
            mode,
            executionCalldata,
            validUntilBlock,
            uint256(0),
            maxTokens,
            spendersZero,
            sig
        );
    }

    function testGuardedTransferAndAntiReplayNonce() public {
        vm.deal(owner, 1 ether);
        address predicted = factory.getAddress(owner, keccak256("salt1"));
        vm.prank(owner);
        address acct = factory.createProtectedAccount{value: 0.001 ether}(owner, keccak256("salt1"));
        assertEq(acct, predicted);
        usdc.mint(acct, 1_000e6);

        address recipient = address(0xCAFE);
        bytes memory callData = abi.encodeWithSelector(TestERC20.transfer.selector, recipient, 250e6);
        bytes memory execData = abi.encodePacked(address(usdc), uint256(0), callData);

        address[] memory spenders = new address[](0);
        bytes memory env = _signEnvelope(acct, 0, execData, block.number + 20, 250e6, spenders);

        vm.prank(owner);
        AegisProtectedSmartAccount(payable(acct)).executeGuarded(env, address(usdc), 0, callData);
        assertEq(usdc.balanceOf(recipient), 250e6);
        assertEq(AegisProtectedSmartAccount(payable(acct)).nonce(), 1);

        vm.prank(owner);
        vm.expectRevert(AegisExecutionHook.AegisInvalidEnclaveSignature.selector);
        AegisProtectedSmartAccount(payable(acct)).executeGuarded(env, address(usdc), 0, callData);
    }

    function testRecipientSubstitutionRejectedOnChain() public {
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        address acct = factory.createProtectedAccount{value: 0.001 ether}(owner, keccak256("salt_sub"));
        usdc.mint(acct, 1_000e6);

        address legitimateRecipient = address(0xCAFE);
        address attackerRecipient = address(0xBAD1);

        bytes memory signedCallData = abi.encodeWithSelector(TestERC20.transfer.selector, legitimateRecipient, 250e6);
        bytes memory signedExecData = abi.encodePacked(address(usdc), uint256(0), signedCallData);
        address[] memory spenders = new address[](0);
        bytes memory env = _signEnvelope(acct, 0, signedExecData, block.number + 20, 250e6, spenders);

        bytes memory spoofedCallData = abi.encodeWithSelector(TestERC20.transfer.selector, attackerRecipient, 250e6);

        vm.prank(owner);
        vm.expectRevert(AegisExecutionHook.AegisCalldataMismatch.selector);
        AegisProtectedSmartAccount(payable(acct)).executeGuarded(env, address(usdc), 0, spoofedCallData);
        assertEq(usdc.balanceOf(attackerRecipient), 0);
    }

    function testCanonicalErc7579ExecuteAndZeroResetApproval() public {
        vm.deal(owner, 1 ether);
        vm.prank(owner);
        address acct = factory.createProtectedAccount{value: 0.001 ether}(owner, keccak256("salt3"));
        usdc.mint(acct, 1_000e6);

        address recipient = address(0xBEEF);
        bytes memory routerCall = abi.encodeWithSelector(
            TestDexRouter.pullExact.selector,
            address(usdc),
            acct,
            recipient,
            400e6
        );
        bytes memory execData = abi.encodePacked(address(router), uint256(0), routerCall);
        address[] memory spenders = new address[](1);
        spenders[0] = address(router);

        bytes memory env = _signEnvelope(acct, 0, execData, block.number + 20, 400e6, spenders);

        vm.prank(owner);
        AegisProtectedSmartAccount(payable(acct)).executeWithZeroResetApproval(
            env,
            address(usdc),
            address(router),
            400e6,
            address(router),
            routerCall
        );

        assertEq(usdc.balanceOf(recipient), 400e6);
        assertEq(usdc.allowance(acct, address(router)), 0);
    }

    function testHardenedAccessControlsAndGovernanceQuorum() public {
        // 1. Unauthenticated postCheck on AegisExecutionHook must revert
        vm.expectRevert(AegisExecutionHook.AegisUnauthorizedAccount.selector);
        hook.postCheck(hex"1234");

        // 2. Unauthenticated fileClaim on AegisUnderwritingVault must revert
        vm.expectRevert(AegisUnderwritingVault.AegisUnauthorized.selector);
        vault.fileClaim(1, address(0x1111), address(0x2222), 100e6);

        // 3. 1-of-5 rogue guardian cannot unilaterally cancel a queued action (requires 3-of-5)
        vm.prank(vm.addr(guardian1Pk));
        uint256 actionId = council.queueAction(address(council), 0, abi.encodeCall(AegisSecurityCouncil.unpauseProtocol, ()));
        vm.prank(vm.addr(guardian2Pk));
        council.cancelAction(actionId);
        (, , , , , uint256 cancelCount, , bool cancelled) = council.actions(actionId);
        assertEq(cancelCount, 1);
        assertFalse(cancelled);

        // 4. PCR0 rotation preserves 24h overlap window for existing active session
        vm.prank(address(council));
        registry.updateApprovedPCR0(keccak256("NEW_PCR0_HIGH"), bytes16(keccak256("NEW_PCR0_LOW")));
        assertTrue(registry.isValidEnclaveSigner(enclaveSigner));

        // 5. 3-of-5 immediate revocation revokes compromised session without 48h timelock
        vm.prank(vm.addr(guardian1Pk));
        council.approveImmediateSessionRevocation(address(registry), enclaveSigner, "Key leak test");
        vm.prank(vm.addr(guardian2Pk));
        council.approveImmediateSessionRevocation(address(registry), enclaveSigner, "Key leak test");
        vm.prank(vm.addr(guardian3Pk));
        council.approveImmediateSessionRevocation(address(registry), enclaveSigner, "Key leak test");
        assertFalse(registry.isValidEnclaveSigner(enclaveSigner));
    }

    function check_outflowConservationSymbolic(uint256 signedCap, uint256 attemptedTransfer) public {
        vm.assume(signedCap < 1_000_000e6);
        vm.assume(attemptedTransfer > signedCap && attemptedTransfer <= 1_000_000e6);

        vm.deal(owner, 1 ether);
        vm.prank(owner);
        address acct = factory.createProtectedAccount{value: 0.001 ether}(owner, keccak256("symbolic_salt"));
        usdc.mint(acct, 1_000_000e6);

        address recipient = address(0xCAFE);
        bytes memory callData = abi.encodeWithSelector(TestERC20.transfer.selector, recipient, attemptedTransfer);
        bytes memory execData = abi.encodePacked(address(usdc), uint256(0), callData);
        address[] memory spenders = new address[](0);
        bytes memory env = _signEnvelope(acct, 0, execData, block.number + 20, signedCap, spenders);

        vm.prank(owner);
        vm.expectRevert();
        AegisProtectedSmartAccount(payable(acct)).executeGuarded(env, address(usdc), 0, callData);
    }
}
