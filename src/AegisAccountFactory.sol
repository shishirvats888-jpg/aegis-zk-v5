// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

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

interface IAegisHookModule {
    function preCheck(address msgSender, uint256 value, bytes calldata msgData) external returns (bytes memory);
    function postCheck(bytes calldata hookData) external;
    function validateUserOpGuard(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 validUntilBlock,
        bytes32 maxOutflowHash,
        bytes calldata enclaveSignature
    ) external view returns (bool);
}

interface IERC20Account {
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract AegisProtectedSmartAccount {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    address public immutable owner;
    IAegisHookModule public immutable aegisHook;
    address public immutable entryPoint;
    uint256 public nonce;

    error AegisOnlyOwnerOrEntryPoint();
    error AegisOnlyEntryPoint();
    error AegisInvalidOwnerSignature();
    error AegisApproveFailed();

    constructor(address _owner, address _aegisHook, address _entryPoint) {
        owner = _owner;
        aegisHook = IAegisHookModule(_aegisHook);
        entryPoint = _entryPoint;
        nonce = 0;
    }

    receive() external payable {}

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != entryPoint) revert AegisOnlyEntryPoint();

        (
            bytes memory ownerSig,
            uint256 validUntilBlock,
            bytes32 maxOutflowHash,
            bytes memory enclaveSignature
        ) = abi.decode(userOp.signature, (bytes, uint256, bytes32, bytes));

        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        if (_recoverOwner(ethSignedHash, ownerSig) != owner) revert AegisInvalidOwnerSignature();

        aegisHook.validateUserOpGuard(userOp, userOpHash, validUntilBlock, maxOutflowHash, enclaveSignature);

        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(entryPoint).call{value: missingAccountFunds}("");
            require(ok, "Aegis: prefund transfer failed");
        }
        return 0;
    }

    function executeGuarded(
        bytes calldata hookEnvelope,
        address target,
        uint256 value,
        bytes calldata callData
    ) external returns (bytes memory result) {
        if (msg.sender != owner && msg.sender != entryPoint) revert AegisOnlyOwnerOrEntryPoint();
        bytes memory hookData = aegisHook.preCheck(msg.sender, value, hookEnvelope);
        nonce += 1;
        if (target != address(0)) {
            (bool ok, bytes memory ret) = target.call{value: value}(callData);
            if (!ok) {
                assembly { revert(add(ret, 32), mload(ret)) }
            }
            result = ret;
        }
        aegisHook.postCheck(hookData);
    }

    function executeWithZeroResetApproval(
        bytes calldata hookEnvelope,
        address token,
        address spender,
        uint256 exactAmount,
        address targetRouter,
        bytes calldata routerCalldata
    ) external returns (bytes memory result) {
        if (msg.sender != owner && msg.sender != entryPoint) revert AegisOnlyOwnerOrEntryPoint();
        bytes memory hookData = aegisHook.preCheck(msg.sender, 0, hookEnvelope);
        nonce += 1;

        if (IERC20Account(token).allowance(address(this), spender) != 0) {
            _safeApprove(token, spender, 0);
        }
        _safeApprove(token, spender, exactAmount);

        (bool ok, bytes memory ret) = targetRouter.call(routerCalldata);
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }
        result = ret;

        _safeApprove(token, spender, 0);
        aegisHook.postCheck(hookData);
    }

    function _safeApprove(address token, address spender, uint256 amount) internal {
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(IERC20Account.approve.selector, spender, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert AegisApproveFailed();
    }

    function _recoverOwner(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert AegisInvalidOwnerSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert AegisInvalidOwnerSignature();
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert AegisInvalidOwnerSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert AegisInvalidOwnerSignature();
        return signer;
    }
}

contract AegisAccountFactory {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    address public immutable aegisHook;
    address public immutable entryPoint;
    address public immutable governanceTimelock;
    address public feeTreasury;
    uint256 public onboardingFeeWei;

    mapping(address => bool) public isAegisAccount;
    uint256 public totalAccountsDeployed;

    event AegisAccountCreated(address indexed account, address indexed owner, bytes32 indexed salt, uint256 feePaid);
    event OnboardingFeeUpdated(uint256 newFeeWei, address newTreasury);

    error AegisInsufficientOnboardingFee(uint256 sent, uint256 required);
    error AegisUnauthorized();
    error AegisZeroAddress();
    error AegisFeeTransferFailed();

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock) revert AegisUnauthorized();
        _;
    }

    constructor(address _aegisHook, address _entryPoint, address _governanceTimelock, address _feeTreasury, uint256 _onboardingFeeWei) {
        if (_aegisHook == address(0) || _entryPoint == address(0) || _feeTreasury == address(0)) revert AegisZeroAddress();
        aegisHook = _aegisHook;
        entryPoint = _entryPoint;
        governanceTimelock = _governanceTimelock;
        feeTreasury = _feeTreasury;
        onboardingFeeWei = _onboardingFeeWei;
    }

    function createProtectedAccount(address owner, bytes32 salt) external payable returns (address account) {
        if (owner == address(0)) revert AegisZeroAddress();
        if (msg.value < onboardingFeeWei) revert AegisInsufficientOnboardingFee(msg.value, onboardingFeeWei);

        bytes32 finalSalt = keccak256(abi.encode(owner, salt));
        AegisProtectedSmartAccount deployed = new AegisProtectedSmartAccount{salt: finalSalt}(owner, aegisHook, entryPoint);
        account = address(deployed);
        require(deployed.nonce() == 0, "Factory: non-zero initial nonce");

        isAegisAccount[account] = true;
        totalAccountsDeployed += 1;

        if (msg.value > 0) {
            (bool ok, ) = feeTreasury.call{value: msg.value}("");
            if (!ok) revert AegisFeeTransferFailed();
        }
        emit AegisAccountCreated(account, owner, salt, msg.value);
    }

    function setOnboardingConfig(uint256 _newFeeWei, address _newTreasury) external onlyGovernance {
        if (_newTreasury == address(0)) revert AegisZeroAddress();
        onboardingFeeWei = _newFeeWei;
        feeTreasury = _newTreasury;
        emit OnboardingFeeUpdated(_newFeeWei, _newTreasury);
    }
}
