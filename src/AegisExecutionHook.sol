// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IEntryPoint {
    function balanceOf(address account) external view returns (uint256);
}

interface IAegisSessionRegistry {
    function isValidEnclaveSigner(address signer) external view returns (bool);
}

interface ISecurityCouncilHook {
    function globalPaused() external view returns (bool);
}

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

contract AegisExecutionHook {
    IAegisSessionRegistry public immutable sessionRegistry;
    IEntryPoint public immutable entryPoint;
    ISecurityCouncilHook public immutable securityCouncil;
    address public immutable approvedPaymaster;
    address public immutable governanceTimelock;
    uint256 public immutable maxAllowedGasPrice;

    bytes1 internal constant CALLTYPE_SINGLE = 0x00;
    bytes1 internal constant CALLTYPE_BATCH = 0x01;
    bytes1 internal constant CALLTYPE_DELEGATECALL = 0xff;
    bytes1 internal constant EXECTYPE_DEFAULT = 0x00;

    bytes4 internal constant SEL_INSTALL_MODULE = 0x9517e29f;
    bytes4 internal constant SEL_UNINSTALL_MODULE = 0xa71763a8;
    bytes4 internal constant SEL_EXEC_FROM_EXECUTOR = 0xd691c964;

    mapping(address => bool) public isCanonicalToken;
    address[] public canonicalTokens;
    uint256 private transient _hookLock;

    struct DailyVelocity {
        uint64 windowStart;
        uint256 spentInWindow;
    }

    mapping(address => mapping(address => uint256)) public dailyOutflowCap;
    mapping(address => mapping(address => DailyVelocity)) public dailyVelocityState;

    struct ExecutionContext {
        address account;
        uint256 validUntilBlock;
        uint256 signedMaxOutflowEth;
        uint256 nativeAndDepositBefore;
        uint256[] tokenBalancesBefore;
        uint256[] signedMaxOutflowTokens;
        address[] spendersToVerifyZero;
    }

    event DailyVelocityCapSet(address indexed account, address indexed asset, uint256 maxDailyOutflow);

    error AegisProtocolPaused();
    error AegisNestedExecutionForbidden();
    error AegisDelegatecallForbidden();
    error AegisNonDefaultExecTypeForbidden();
    error AegisSelfCallForbidden();
    error AegisUnauthorizedModuleMutation();
    error AegisInvalidPaymaster();
    error AegisGasPriceExceeded();
    error AegisExpiredSignature(uint256 currentBlock, uint256 validUntilBlock);
    error AegisInvalidEnclaveSignature();
    error AegisEthOutflowExceeded(uint256 beforeBal, uint256 afterBal, uint256 maxAllowed);
    error AegisTokenOutflowExceeded(address token, uint256 beforeBal, uint256 afterBal, uint256 maxAllowed);
    error AegisDailyVelocityExceeded(address account, address asset, uint256 attemptedTotal, uint256 dailyCap);
    error AegisNonZeroAllowanceRemaining(address token, address spender, uint256 remaining);
    error AegisNonCanonicalToken(address token);
    error AegisArrayLengthMismatch();

    constructor(address _sessionRegistry, address _entryPoint, address _securityCouncil, address _approvedPaymaster, address _governanceTimelock, uint256 _maxAllowedGasPrice, address[] memory _canonicalTokens) {
        sessionRegistry = IAegisSessionRegistry(_sessionRegistry);
        entryPoint = IEntryPoint(_entryPoint);
        securityCouncil = ISecurityCouncilHook(_securityCouncil);
        approvedPaymaster = _approvedPaymaster;
        governanceTimelock = _governanceTimelock;
        maxAllowedGasPrice = _maxAllowedGasPrice;

        for (uint256 i = 0; i < _canonicalTokens.length; i++) {
            isCanonicalToken[_canonicalTokens[i]] = true;
            canonicalTokens.push(_canonicalTokens[i]);
        }
    }

    function setDailyOutflowCap(address account, address asset, uint256 maxDailyOutflow) external {
        require(msg.sender == account || msg.sender == governanceTimelock, "Aegis: unauthorized cap setter");
        dailyOutflowCap[account][asset] = maxDailyOutflow;
        emit DailyVelocityCapSet(account, asset, maxDailyOutflow);
    }

    function validateUserOpGuard(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 validUntilBlock, bytes32 maxOutflowHash, bytes calldata enclaveSignature) external view returns (bool) {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) revert AegisProtocolPaused();
        if (userOp.paymasterAndData.length < 20 || address(bytes20(userOp.paymasterAndData[:20])) != approvedPaymaster) revert AegisInvalidPaymaster();
        if (tx.gasprice > maxAllowedGasPrice) revert AegisGasPriceExceeded();

        if (userOp.callData.length >= 4) {
            bytes4 selector = bytes4(userOp.callData[:4]);
            if ((selector == SEL_INSTALL_MODULE || selector == SEL_UNINSTALL_MODULE || selector == SEL_EXEC_FROM_EXECUTOR) && msg.sender != governanceTimelock) {
                revert AegisUnauthorizedModuleMutation();
            }
        }

        bytes32 digest = keccak256(abi.encode(userOpHash, block.chainid, userOp.sender, validUntilBlock, maxOutflowHash));
        address recovered = _recoverSigner(digest, enclaveSignature);
        if (!sessionRegistry.isValidEnclaveSigner(recovered)) revert AegisInvalidEnclaveSignature();
        return true;
    }

    function preCheck(address msgSender, uint256, bytes calldata msgData) external returns (bytes memory hookData) {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) revert AegisProtocolPaused();
        if (_hookLock != 0) revert AegisNestedExecutionForbidden();
        _hookLock = 1;

        address account = msg.sender;
        (bytes32 mode, bytes memory executionCalldata, uint256 validUntilBlock, uint256 signedMaxOutflowEth, uint256[] memory signedMaxOutflowTokens, address[] memory spendersToVerifyZero) =
            abi.decode(msgData, (bytes32, bytes, uint256, uint256, uint256[], address[]));

        if (block.number > validUntilBlock) revert AegisExpiredSignature(block.number, validUntilBlock);
        if (signedMaxOutflowTokens.length != canonicalTokens.length) revert AegisArrayLengthMismatch();

        bytes1 callType = bytes1(mode);
        bytes1 execType = bytes1(mode << 8);
        if (callType == CALLTYPE_DELEGATECALL) revert AegisDelegatecallForbidden();
        if (execType != EXECTYPE_DEFAULT) revert AegisNonDefaultExecTypeForbidden();
        if (msgSender != governanceTimelock) _assertNoSelfCalls(account, callType, executionCalldata);

        uint256 nativeAndDepositBefore = account.balance + entryPoint.balanceOf(account);
        uint256 len = canonicalTokens.length;
        uint256[] memory tokenBalancesBefore = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            tokenBalancesBefore[i] = IERC20(canonicalTokens[i]).balanceOf(account);
        }

        return abi.encode(ExecutionContext(account, validUntilBlock, signedMaxOutflowEth, nativeAndDepositBefore, tokenBalancesBefore, signedMaxOutflowTokens, spendersToVerifyZero));
    }

    function postCheck(bytes calldata hookData) external {
        ExecutionContext memory ctx = abi.decode(hookData, (ExecutionContext));
        if (block.number > ctx.validUntilBlock) revert AegisExpiredSignature(block.number, ctx.validUntilBlock);

        uint256 nativeAndDepositAfter = ctx.account.balance + entryPoint.balanceOf(ctx.account);
        if (nativeAndDepositAfter + ctx.signedMaxOutflowEth < ctx.nativeAndDepositBefore) {
            revert AegisEthOutflowExceeded(ctx.nativeAndDepositBefore, nativeAndDepositAfter, ctx.signedMaxOutflowEth);
        }
        if (ctx.nativeAndDepositBefore > nativeAndDepositAfter) {
            _recordAndCheckDailyVelocity(ctx.account, address(0), ctx.nativeAndDepositBefore - nativeAndDepositAfter);
        }

        uint256 len = canonicalTokens.length;
        for (uint256 i = 0; i < len; i++) {
            address token = canonicalTokens[i];
            uint256 balAfter = IERC20(token).balanceOf(ctx.account);
            if (balAfter + ctx.signedMaxOutflowTokens[i] < ctx.tokenBalancesBefore[i]) {
                revert AegisTokenOutflowExceeded(token, ctx.tokenBalancesBefore[i], balAfter, ctx.signedMaxOutflowTokens[i]);
            }
            if (ctx.tokenBalancesBefore[i] > balAfter) {
                _recordAndCheckDailyVelocity(ctx.account, token, ctx.tokenBalancesBefore[i] - balAfter);
            }
            for (uint256 j = 0; j < ctx.spendersToVerifyZero.length; j++) {
                uint256 rem = IERC20(token).allowance(ctx.account, ctx.spendersToVerifyZero[j]);
                if (rem != 0) revert AegisNonZeroAllowanceRemaining(token, ctx.spendersToVerifyZero[j], rem);
            }
        }
        _hookLock = 0;
    }

    function executeWithZeroResetApproval(address token, address spender, uint256 exactAmount, address targetRouter, bytes calldata routerCalldata) external returns (bytes memory result) {
        if (!isCanonicalToken[token]) revert AegisNonCanonicalToken(token);
        if (IERC20(token).allowance(address(this), spender) != 0) _safeApprove(token, spender, 0);
        _safeApprove(token, spender, exactAmount);
        (bool success, bytes memory ret) = targetRouter.call(routerCalldata);
        require(success, "Aegis: router call failed");
        _safeApprove(token, spender, 0);
        return ret;
    }

    function _recordAndCheckDailyVelocity(address account, address asset, uint256 actualOutflow) internal {
        uint256 cap = dailyOutflowCap[account][asset];
        if (cap == 0) return;
        DailyVelocity storage vel = dailyVelocityState[account][asset];
        if (block.timestamp >= vel.windowStart + 24 hours) {
            vel.windowStart = uint64(block.timestamp);
            vel.spentInWindow = actualOutflow;
        } else {
            vel.spentInWindow += actualOutflow;
        }
        if (vel.spentInWindow > cap) revert AegisDailyVelocityExceeded(account, asset, vel.spentInWindow, cap);
    }

    function _assertNoSelfCalls(address account, bytes1 callType, bytes memory executionCalldata) internal pure {
        if (callType == CALLTYPE_SINGLE) {
            require(executionCalldata.length >= 20, "Aegis: short single calldata");
            address target;
            assembly { target := shr(96, mload(add(executionCalldata, 32))) }
            if (target == account) revert AegisSelfCallForbidden();
        } else if (callType == CALLTYPE_BATCH) {
            Execution[] memory execs = abi.decode(executionCalldata, (Execution[]));
            for (uint256 i = 0; i < execs.length; i++) {
                if (execs[i].target == account) revert AegisSelfCallForbidden();
            }
        }
    }

    struct Execution { address target; uint256 value; bytes callData; }

    function _safeApprove(address token, address spender, uint256 amount) internal {
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.approve.selector, spender, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "Aegis: approve failed");
    }

    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert AegisInvalidEnclaveSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert AegisInvalidEnclaveSignature();
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert AegisInvalidEnclaveSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert AegisInvalidEnclaveSignature();
        return signer;
    }
}
