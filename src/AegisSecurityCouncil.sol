// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AegisSecurityCouncil {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    uint256 public constant REQUIRED_SIGNATURES = 3;
    uint256 public constant TOTAL_GUARDIANS = 5;
    uint256 public constant TIMELOCK_DELAY = 48 hours;

    mapping(address => bool) public isGuardian;
    address public guardians;
    bool public globalPaused;
    uint256 public pausedAt;

    struct QueuedAction {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 approvals;
        bool executed;
        bool cancelled;
    }

    uint256 public nextActionId = 1;
    mapping(uint256 => QueuedAction) public actions;
    mapping(uint256 => mapping(address => bool)) public hasApproved;

    event ActionQueued(uint256 indexed actionId, address indexed target, bytes data, uint256 eta);
    event ActionApproved(uint256 indexed actionId, address indexed guardian, uint256 totalApprovals);
    event ActionExecuted(uint256 indexed actionId, address indexed target);
    event ActionCancelled(uint256 indexed actionId, address indexed guardian);
    event EmergencyPaused(address indexed guardian, uint256 timestamp);
    event EmergencyUnpaused(uint256 indexed actionId);

    error AegisNotGuardian();
    error AegisInvalidGuardianSet();
    error AegisAlreadyApproved();
    error AegisInsufficientApprovals(uint256 current, uint256 required);
    error AegisTimelockNotElapsed(uint256 currentTs, uint256 eta);
    error AegisActionAlreadyFinalized();
    error AegisExecutionFailed();

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert AegisNotGuardian();
        _;
    }

    constructor(address memory _guardians) {
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

    function unpauseProtocol() external {
        if (msg.sender != address(this)) revert AegisNotGuardian();
        globalPaused = false;
        emit EmergencyUnpaused(0);
    }

    function queueAction(address target, uint256 value, bytes calldata data) external onlyGuardian returns (uint256 actionId) {
        actionId = nextActionId++;
        uint256 eta = block.timestamp + TIMELOCK_DELAY;
        actions[actionId] = QueuedAction(target, value, data, eta, 1, false, false);
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

    function cancelAction(uint256 actionId) external onlyGuardian {
        QueuedAction storage act = actions[actionId];
        if (act.eta == 0 || act.executed || act.cancelled) revert AegisActionAlreadyFinalized();
        act.cancelled = true;
        emit ActionCancelled(actionId, msg.sender);
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
