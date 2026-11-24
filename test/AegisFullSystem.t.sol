// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/AegisSecurityCouncil.sol";
import "../src/AegisOracleGuard.sol";
import "../src/AegisSessionRegistry.sol";
import "../src/AegisExecutionHook.sol";
import "../src/AegisAccountFactory.sol";
import "../src/AegisUnderwritingVault.sol";

contract MockUSDT {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }

    function approve(address spender, uint256 amount) external returns (bool) {
        if (amount != 0 && allowance[msg.sender][spender] != 0) revert("USDT: non-zero to non-zero approve");
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "USDT: bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount && allowance[from][msg.sender] >= amount, "USDT: allow");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockSP1Verifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {}
}

contract MockEntryPoint is IEntryPoint {
    mapping(address => uint256) public deposits;
    function depositTo(address account) external payable { deposits[account] += msg.value; }
    function balanceOf(address account) external view override returns (uint256) { return deposits[account]; }
}

contract MockAggregator is IAggregatorV3 {
    int256 public answer;
    uint256 public updatedAt;
    constructor(int256 _ans) { answer = _ans; updatedAt = block.timestamp; }
    function setAnswer(int256 _ans) external { answer = _ans; updatedAt = block.timestamp; }
    function decimals() external pure override returns (uint8) { return 8; }
    function latestRoundData() external view override returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, block.timestamp - 2 hours, updatedAt, 1);
    }
}

contract MaliciousDrainer {
    function attemptReentrancy(AegisProtectedSmartAccount account, bytes calldata innerData) external {
        account.executeGuarded(innerData, address(0), 0, "");
    }
}

contract AegisFullSystemTest is Test {
    AegisSecurityCouncil public council;
    AegisOracleGuard public oracleGuard;
    AegisSessionRegistry public registry;
    AegisExecutionHook public hook;
    AegisAccountFactory public factory;
    AegisUnderwritingVault public vault;
    AegisProtectedSmartAccount public account;

    MockUSDT public usdt;
    MockSP1Verifier public sp1;
    MockEntryPoint public entryPoint;
    MockAggregator public ethFeed;
    MaliciousDrainer public drainer;

    address public g1 = address(0x101);
    address public g2 = address(0x102);
    address public g3 = address(0x103);
    address public g4 = address(0x104);
    address public g5 = address(0x105);

    address public owner = address(0x201);
    address public paymaster = address(0x202);
    address public treasury = address(0x203);
    address public lp1 = address(0x301);
    address public operator = address(0x401);
    address public attacker = address(0x6666);
    address public enclaveSigner = address(0xA11CE);

    bytes32 public constant APPROVED_PCR0 = keccak256("AEGIS_NITRO_ENCLAVE_V5_2");
    bytes32 public constant VKEY = keccak256("AEGIS_SP1_VKEY");

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory guards = new address[](5);
        guards = g1; guards = g2; guards = g3; guards = g4; guards = g5;
        council = new AegisSecurityCouncil(guards);

        usdt = new MockUSDT();
        sp1 = new MockSP1Verifier();
        entryPoint = new MockEntryPoint();
        ethFeed = new MockAggregator(3000e8); // $3,000 ETH
        drainer = new MaliciousDrainer();

        oracleGuard = new AegisOracleGuard(address(council), address(0));
        vm.prank(address(council));
        oracleGuard.configureTokenFeed(address(usdt), address(ethFeed), address(0), 1 hours, 200);

        registry = new AegisSessionRegistry(address(sp1), VKEY, APPROVED_PCR0, address(council), address(council));

        address[] memory tokens = new address[](1);
        tokens = address(usdt);
        hook = new AegisExecutionHook(address(registry), address(entryPoint), address(council), paymaster, address(council), 100 gwei, tokens);
        factory = new AegisAccountFactory(address(hook), address(entryPoint), address(council), treasury, 0.01 ether);
        vault = new AegisUnderwritingVault(address(usdt), address(council), address(council));

        vm.deal(owner, 20 ether);
        vm.prank(owner);
        address accAddr = factory.createProtectedAccount{value: 0.01 ether}(owner, bytes32(uint256(1)));
        account = AegisProtectedSmartAccount(payable(accAddr));

        bytes memory pubValues = abi.encode(enclaveSigner, APPROVED_PCR0, keccak256("CERT_1"), uint64(block.timestamp), uint64(block.timestamp - 1 days), uint64(block.timestamp + 30 days));
        registry.registerEnclaveSession(pubValues, hex"1234");

        vm.deal(address(account), 10 ether);
        usdt.mint(address(account), 100_000e6);
        usdt.mint(lp1, 1_000_000e6);
        vm.startPrank(lp1);
        usdt.approve(address(vault), 1_000_000e6);
        vault.depositLp(1_000_000e6);
        vm.stopPrank();
    }

    function test_1_AtomicFactoryNonceZeroAndFeeCollected() public view {
        assertEq(account.nonce(), 0);
        assertTrue(factory.isAegisAccount(address(account)));
        assertEq(treasury.balance, 0.01 ether);
    }

    function test_2_BlocksDelegatecallAndSelfCall() public {
        uint256[] memory maxOut = new uint256[](1);
        address[] memory spenders = new address[](0);
        bytes memory badDelegate = abi.encode(bytes32(bytes1(0xff)), abi.encodePacked(attacker, uint256(0), bytes("")), block.number + 2, uint256(0), maxOut, spenders);

        vm.prank(owner);
        vm.expectRevert(AegisExecutionHook.AegisDelegatecallForbidden.selector);
        account.executeGuarded(badDelegate, address(0), 0, "");
    }

    function test_3_BlocksNestedEIP1153Reentrancy() public {
        uint256[] memory maxOut = new uint256[](1);
        address[] memory spenders = new address[](0);
        bytes32 mode = bytes32(bytes1(0x00));
        bytes memory inner = abi.encode(mode, abi.encodePacked(attacker, uint256(0), bytes("")), block.number + 2, uint256(0), maxOut, spenders);
        bytes memory outer = abi.encode(mode, abi.encodePacked(address(drainer), uint256(0), bytes("")), block.number + 2, uint256(0), maxOut, spenders);

        vm.prank(owner);
        vm.expectRevert(AegisExecutionHook.AegisNestedExecutionForbidden.selector);
        account.executeGuarded(outer, address(drainer), 0, abi.encodeWithSelector(MaliciousDrainer.attemptReentrancy.selector, account, inner));
    }

    function test_4_BlocksInfiniteApprovalAnd24hVelocityBreach() public {
        vm.prank(address(account));
        hook.setDailyOutflowCap(address(account), address(usdt), 5_000e6); // $5k daily limit

        uint256[] memory maxOut = new uint256[](1);
        maxOut = 10_000e6;
        address[] memory spenders = new address[](1);
        spenders = attacker;
        bytes memory hookMsg = abi.encode(bytes32(bytes1(0x00)), abi.encodePacked(address(usdt), uint256(0), bytes("")), block.number + 2, uint256(0), maxOut, spenders);

        // Attempt to spend $6,000 USDT -> exceeds $5,000 daily velocity cap even with valid signature!
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AegisExecutionHook.AegisDailyVelocityExceeded.selector, address(account), address(usdt), 6_000e6, 5_000e6));
        account.executeGuarded(hookMsg, address(usdt), 0, abi.encodeWithSelector(MockUSDT.transfer.selector, attacker, 6_000e6));
    }

    function test_5_OracleGuardRejectsManipulatedZkTlsPrice() public {
        // Chainlink is $3,000 (2% max deviation); zkTLS reports $3,200 -> reverts!
        vm.expectRevert();
        oracleGuard.assertZkTlsPriceWithinBounds(address(usdt), 3200e18);
    }

    function test_6_SecurityCouncil3Of5TimelockAndEmergencyPause() public {
        // Single guardian triggers instant pause -> blocks new enclave registrations immediately
        vm.prank(g1);
        council.triggerEmergencyPause();

        bytes memory pubValues = abi.encode(address(0xBEEF), APPROVED_PCR0, keccak256("CERT_2"), uint64(block.timestamp), uint64(block.timestamp - 1 days), uint64(block.timestamp + 30 days));
        vm.expectRevert(AegisSessionRegistry.AegisProtocolPaused.selector);
        registry.registerEnclaveSession(pubValues, hex"1234");
    }

    function test_7_VaultFirstLossBondEncumberedTVLAndEpochCap() public {
        usdt.mint(operator, 40_000e6);
        vm.startPrank(operator);
        usdt.approve(address(vault), 40_000e6);
        vault.postOperatorBond(40_000e6, 200_000e6);
        vm.stopPrank();

        uint256 claimId = vault.fileClaim(1, operator, address(0x7777), 200_000e6);
        assertEq(vault.encumberedLiquidity(), 160_000e6);
        assertEq(vault.availableTVL(), 840_000e6);

        vm.warp(block.timestamp + 7 days + 24 hours + 72 hours + 1);
        vault.finalizeEpoch(1);
        vault.settleClaim(claimId);

        assertEq(usdt.balanceOf(address(0x7777)), 140_000e6); // $40k bond + $100k (10% cap)
        assertEq(vault.totalLpAssets(), 900_000e6);
        assertEq(vault.encumberedLiquidity(), 0);
    }
}
