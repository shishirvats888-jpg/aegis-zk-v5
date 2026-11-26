// Created & Architected by Shishir Vats | AEGIS-ZK (v5.3 Hardened Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISessionRegistryRevoker {
    function emergencyRevokeSession(address enclaveSigner, string calldata reason) external;
}

contract AegisSecurityCouncil {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.3-SHISHIR-VATS";

    uint256 public constant REQUIRED_SIGNATURES = 3;
    uint256 public constant TOTAL_GUARDIANS = 5;
    uint256 public constant TIMELOCK_DELAY = 48 hours;

    mapping(address => bool) public isGuardian;
    address[5] public guardians;
    bool public globalPaused;
    uint256 public pausedAt;

    struct QueuedAction {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 approvals;
        uint256 cancelApprovals;
        bool executed;
        bool cancelled;
    }

    uint256 public nextActionId = 1;
    mapping(uint256 => QueuedAction) public actions;
    mapping(uint256 => mapping(address => bool)) public hasApproved;
    mapping(uint256 => mapping(address => bool)) public hasApprovedCancel;

    mapping(bytes32 => uint256) public fastRevokeApprovals;
    mapping(bytes32 => mapping(address => bool)) public hasApprovedFastRevoke;

    event ActionQueued(uint256 indexed actionId, address indexed target, bytes data, uint256 eta);
    event ActionApproved(uint256 indexed actionId, address indexed guardian, uint256 totalApprovals);
    event ActionCancelApproved(uint256 indexed actionId, address indexed guardian, uint256 totalCancelApprovals);
    event ActionExecuted(uint256 indexed actionId, address indexed target);
    event ActionCancelled(uint256 indexed actionId, address indexed guardian);
    event GuardianRotated(uint256 indexed index, address indexed oldGuardian, address indexed newGuardian);
    event FastRevocationApproved(bytes32 indexed revokeId, address indexed enclaveSigner, uint256 approvals);
    event FastRevocationExecuted(bytes32 indexed revokeId, address indexed enclaveSigner);
    event EmergencyPaused(address indexed guardian, uint256 timestamp);
    event EmergencyUnpaused(uint256 indexed actionId);

    error AegisNotGuardian();
    error AegisOnlySelfGovernance();
    error AegisInvalidGuardianSet();
    error AegisInvalidGuardianIndex();
    error AegisAlreadyApproved();
    error AegisInsufficientApprovals(uint256 current, uint256 required);
    error AegisTimelockNotElapsed(uint256 currentTs, uint256 eta);
    error AegisActionAlreadyFinalized();
    error AegisExecutionFailed();

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert AegisNotGuardian();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert AegisOnlySelfGovernance();
        _;
    }

    constructor(address[5] memory _guardians) {
        for (uint256 i = 0; i < TOTAL_GUARDIANS; i++) {
            address g = _guardians[i];
            if (g == address(0) || isGuardian[g]) revert AegisInvalidGuardianSet();
            isGuardian[g] = true;
            guardians[i] = g;
        }
    }

    function triggerEmergencyPause() external onlyGuardian {
        globalPaused = true;
        pausedAt = block.timestamp;
        emit EmergencyPaused(msg.sender, block.timestamp);
    }

    function unpauseProtocol() external onlySelf {
        globalPaused = false;
        emit EmergencyUnpaused(0);
    }

    function rotateGuardian(uint256 index, address newGuardian) external onlySelf {
        if (index >= TOTAL_GUARDIANS) revert AegisInvalidGuardianIndex();
        if (newGuardian == address(0) || isGuardian[newGuardian]) revert AegisInvalidGuardianSet();
        address oldGuardian = guardians[index];
        isGuardian[oldGuardian] = false;
        isGuardian[newGuardian] = true;
        guardians[index] = newGuardian;
        emit GuardianRotated(index, oldGuardian, newGuardian);
    }

    // 3-of-5 immediate session revocation without 48h timelock (since SESSION_TTL is 24h)
    function approveImmediateSessionRevocation(
        address registry,
        address enclaveSigner,
        string calldata reason
    ) external onlyGuardian {
        bytes32 revokeId = keccak256(abi.encode(registry, enclaveSigner, reason));
        if (hasApprovedFastRevoke[revokeId][msg.sender]) revert AegisAlreadyApproved();
        hasApprovedFastRevoke[revokeId][msg.sender] = true;
        uint256 count = ++fastRevokeApprovals[revokeId];
        emit FastRevocationApproved(revokeId, enclaveSigner, count);

        if (count == REQUIRED_SIGNATURES) {
            ISessionRegistryRevoker(registry).emergencyRevokeSession(enclaveSigner, reason);
            emit FastRevocationExecuted(revokeId, enclaveSigner);
        }
    }

    function queueAction(address target, uint256 value, bytes calldata data) external onlyGuardian returns (uint256 actionId) {
        actionId = nextActionId++;
        uint256 eta = block.timestamp + TIMELOCK_DELAY;
        actions[actionId] = QueuedAction(target, value, data, eta, 1, 0, false, false);
        hasApproved[actionId][msg.sender] = true;
        emit ActionQueued(actionId, target, data, eta);
        emit ActionApproved(actionId, msg.sender, 1);
    }

    function approveAction(uint256 actionId) external onlyGuardian {
        QueuedAction storage act = actions[actionId];
        if (act.eta == 0 || act.executed || act.cancelled) revert AegisActionAlreadyFinalized();
        if (hasApproved[actionId][msg.sender]) revert AegisAlreadyApproved();
        hasApproved[actionId][msg.sender] = true;
        act.approvals += 1;
        emit ActionApproved(actionId, msg.sender, act.approvals);
    }

    // Requires 3-of-5 guardian approvals so 1 rogue guardian cannot censor governance
    function cancelAction(uint256 actionId) external onlyGuardian {
        QueuedAction storage act = actions[actionId];
        if (act.eta == 0 || act.executed || act.cancelled) revert AegisActionAlreadyFinalized();
        if (hasApprovedCancel[actionId][msg.sender]) revert AegisAlreadyApproved();
        hasApprovedCancel[actionId][msg.sender] = true;
        act.cancelApprovals += 1;
        emit ActionCancelApproved(actionId, msg.sender, act.cancelApprovals);

        if (act.cancelApprovals >= REQUIRED_SIGNATURES) {
            act.cancelled = true;
            emit ActionCancelled(actionId, msg.sender);
        }
    }

    function executeAction(uint256 actionId) external onlyGuardian returns (bytes memory ret) {
        QueuedAction storage act = actions[actionId];
        if (act.eta == 0 || act.executed || act.cancelled) revert AegisActionAlreadyFinalized();
        if (act.approvals < REQUIRED_SIGNATURES) revert AegisInsufficientApprovals(act.approvals, REQUIRED_SIGNATURES);
        if (block.timestamp < act.eta) revert AegisTimelockNotElapsed(block.timestamp, act.eta);
        act.executed = true;
        (bool ok, bytes memory result) = act.target.call{value: act.value}(act.data);
        if (!ok) revert AegisExecutionFailed();
        emit ActionExecuted(actionId, act.target);
        return result;
    }

    receive() external payable {}
}
