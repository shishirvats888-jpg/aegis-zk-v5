// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAegisHookModule {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    function preCheck(address msgSender, uint256 value, bytes calldata msgData) external returns (bytes memory);
    function postCheck(bytes calldata hookData) external;
}

contract AegisProtectedSmartAccount {
    address public immutable owner;
    IAegisHookModule public immutable aegisHook;
    address public immutable entryPoint;
    uint256 public nonce;

    error AegisOnlyOwnerOrEntryPoint();

    constructor(address _owner, address _aegisHook, address _entryPoint) {
        owner = _owner;
        aegisHook = IAegisHookModule(_aegisHook);
        entryPoint = _entryPoint;
        nonce = 0;
    }

    receive() external payable {}

    function executeGuarded(bytes calldata hookEnvelope, address target, uint256 value, bytes calldata callData) external returns (bytes memory result) {
        if (msg.sender != owner && msg.sender != entryPoint) revert AegisOnlyOwnerOrEntryPoint();
        nonce += 1;
        bytes memory hookData = aegisHook.preCheck(msg.sender, value, hookEnvelope);
        if (target != address(0)) {
            (bool ok, bytes memory ret) = target.call{value: value}(callData);
            if (!ok) {
                assembly { revert(add(ret, 32), mload(ret)) }
            }
            result = ret;
        }
        aegisHook.postCheck(hookData);
    }
}

contract AegisAccountFactory {
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
