// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Vault {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ISecurityCouncilVault {
    function globalPaused() external view returns (bool);
}

contract AegisUnderwritingVault {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    IERC20Vault public immutable usdc;
    ISecurityCouncilVault public immutable securityCouncil;
    address public immutable governanceTimelock;

    uint256 public constant EPOCH_DURATION = 7 days;
    uint256 public constant GRACE_PERIOD = 24 hours;
    uint256 public constant DISPUTE_WINDOW = 72 hours;
    uint256 public constant MAX_EPOCH_CAP_BPS = 1000;
    uint256 public constant FIRST_LOSS_BPS = 2000;
    uint256 public constant BPS_DENOMINATOR = 10_000;

    uint256 public totalLpAssets;
    uint256 public totalShares;
    uint256 public protocolReserve;
    uint256 public encumberedLiquidity;

    uint256 public currentEpoch;
    uint256 public currentEpochStart;

    struct EpochInfo {
        uint256 startTime;
        uint256 endTime;
        uint256 availableTVLAtStart;
        uint256 maxCapAmount;
        uint256 totalValidClaimed;
        uint256 totalSlashedDisputed;
        bool finalized;
    }

    struct Claim {
        uint256 epochId;
        address operator;
        address claimant;
        uint256 requestedAmount;
        uint256 bondSlashed;
        uint256 vaultPortion;
        bool disputed;
        bool settled;
    }

    struct WithdrawalRequest {
        uint256 shares;
        uint256 unlockEpoch;
    }

    mapping(uint256 => EpochInfo) public epochs;
    mapping(address => uint256) public lpShares;
    mapping(address => WithdrawalRequest) public withdrawalQueue;
    mapping(address => uint256) public operatorBonds;
    mapping(address => uint256) public operatorCoverageLimit;
    mapping(uint256 => Claim) public claims;
    uint256 public nextClaimId = 1;

    event LpDeposited(address indexed lp, uint256 assets, uint256 shares);
    event LpWithdrawalQueued(address indexed lp, uint256 shares, uint256 unlockEpoch);
    event LpWithdrawn(address indexed lp, uint256 shares, uint256 assets);
    event OperatorBondPosted(address indexed operator, uint256 bondAmount, uint256 coverageLimit);
    event PremiumPaid(address indexed operator, uint256 amount);
    event ClaimFiled(uint256 indexed claimId, uint256 indexed epochId, address indexed operator, uint256 amount);
    event ClaimDisputedAndSlashed(uint256 indexed claimId, address indexed challenger);
    event EpochFinalized(uint256 indexed epochId, uint256 totalValidVaultClaims, uint256 capApplied);
    event ClaimSettled(uint256 indexed claimId, address indexed claimant, uint256 totalPaid);

    error AegisProtocolPaused();
    error AegisZeroAmount();
    error AegisInsufficientShares();
    error AegisWithdrawalLocked(uint256 currentEpoch, uint256 unlockEpoch);
    error AegisInsufficientOperatorBond(uint256 required, uint256 provided);
    error AegisGracePeriodClosed();
    error AegisDisputeWindowActive();
    error AegisDisputeWindowClosed();
    error AegisEpochNotReadyForFinalization();
    error AegisEpochNotFinalized();
    error AegisClaimAlreadySettled();
    error AegisClaimDisputed();
    error AegisUnauthorized();
    error AegisSolvencyViolation();

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock) revert AegisUnauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) revert AegisProtocolPaused();
        _;
    }

    constructor(address _usdc, address _governanceTimelock, address _securityCouncil) {
        usdc = IERC20Vault(_usdc);
        governanceTimelock = _governanceTimelock;
        securityCouncil = ISecurityCouncilVault(_securityCouncil);

        currentEpoch = 1;
        currentEpochStart = block.timestamp;
        epochs[1] = EpochInfo(block.timestamp, block.timestamp + EPOCH_DURATION, 0, 0, 0, 0, false);
    }

    function depositLp(uint256 assets) external whenNotPaused returns (uint256 shares) {
        if (assets == 0) revert AegisZeroAmount();
        _rollEpochIfNeeded();
        shares = (totalShares == 0 || totalLpAssets == 0) ? assets : (assets * totalShares) / totalLpAssets;
        require(usdc.transferFrom(msg.sender, address(this), assets), "Vault: transferFrom failed");
        totalLpAssets += assets;
        totalShares += shares;
        lpShares[msg.sender] += shares;

        EpochInfo storage ep = epochs[currentEpoch];
        if (ep.totalValidClaimed == 0 && ep.availableTVLAtStart == 0) {
            uint256 avail = availableTVL();
            ep.availableTVLAtStart = avail;
            ep.maxCapAmount = (avail * MAX_EPOCH_CAP_BPS) / BPS_DENOMINATOR;
        }
        emit LpDeposited(msg.sender, assets, shares);
    }

    function queueWithdrawal(uint256 shares) external whenNotPaused {
        if (shares == 0) revert AegisZeroAmount();
        if (lpShares[msg.sender] < shares) revert AegisInsufficientShares();
        _rollEpochIfNeeded();
        withdrawalQueue[msg.sender] = WithdrawalRequest(shares, currentEpoch + 1);
        emit LpWithdrawalQueued(msg.sender, shares, currentEpoch + 1);
    }

    function executeWithdrawal() external whenNotPaused {
        _rollEpochIfNeeded();
        WithdrawalRequest memory req = withdrawalQueue[msg.sender];
        if (req.shares == 0) revert AegisZeroAmount();
        if (currentEpoch < req.unlockEpoch) revert AegisWithdrawalLocked(currentEpoch, req.unlockEpoch);

        uint256 prevEpoch = req.unlockEpoch - 1;
        if (!epochs[prevEpoch].finalized && epochs[prevEpoch].totalValidClaimed > 0) revert AegisEpochNotFinalized();

        uint256 assets = (req.shares * totalLpAssets) / totalShares;
        if (totalLpAssets - assets < encumberedLiquidity) revert AegisSolvencyViolation();

        delete withdrawalQueue[msg.sender];
        lpShares[msg.sender] -= req.shares;
        totalShares -= req.shares;
        totalLpAssets -= assets;
        require(usdc.transfer(msg.sender, assets), "Vault: transfer failed");
        emit LpWithdrawn(msg.sender, req.shares, assets);
    }

    function postOperatorBond(uint256 bondAmount, uint256 desiredCoverageLimit) external whenNotPaused {
        uint256 requiredBond = (desiredCoverageLimit * FIRST_LOSS_BPS) / BPS_DENOMINATOR;
        if (bondAmount < requiredBond) revert AegisInsufficientOperatorBond(requiredBond, bondAmount);
        require(usdc.transferFrom(msg.sender, address(this), bondAmount), "Vault: bond transfer failed");
        operatorBonds[msg.sender] += bondAmount;
        operatorCoverageLimit[msg.sender] += desiredCoverageLimit;
        emit OperatorBondPosted(msg.sender, bondAmount, operatorCoverageLimit[msg.sender]);
    }

    function payCoveragePremium(uint256 amount) external whenNotPaused {
        if (amount == 0) revert AegisZeroAmount();
        require(usdc.transferFrom(msg.sender, address(this), amount), "Vault: premium transfer failed");
        uint256 reserveCut = (amount * 2000) / BPS_DENOMINATOR;
        protocolReserve += reserveCut;
        totalLpAssets += (amount - reserveCut);
        emit PremiumPaid(msg.sender, amount);
    }

    function fileClaim(uint256 epochId, address operator, address claimant, uint256 lossAmount) external whenNotPaused returns (uint256 claimId) {
        if (lossAmount == 0) revert AegisZeroAmount();
        _rollEpochIfNeeded();
        EpochInfo storage ep = epochs[epochId];
        if (block.timestamp > ep.endTime + GRACE_PERIOD) revert AegisGracePeriodClosed();

        uint256 coveredLoss = lossAmount > operatorCoverageLimit[operator] ? operatorCoverageLimit[operator] : lossAmount;
        uint256 bondAvailable = operatorBonds[operator];
        uint256 bondSlashed = coveredLoss <= bondAvailable ? coveredLoss : bondAvailable;
        operatorBonds[operator] -= bondSlashed;

        uint256 vaultPortion = coveredLoss - bondSlashed;
        if (vaultPortion > 0) {
            if (encumberedLiquidity + vaultPortion > totalLpAssets + protocolReserve) revert AegisSolvencyViolation();
            encumberedLiquidity += vaultPortion;
            ep.totalValidClaimed += vaultPortion;
        }

        claimId = nextClaimId++;
        claims[claimId] = Claim(epochId, operator, claimant, coveredLoss, bondSlashed, vaultPortion, false, false);
        emit ClaimFiled(claimId, epochId, operator, coveredLoss);
    }

    function disputeSybilClaim(uint256 claimId) external onlyGovernance {
        Claim storage c = claims[claimId];
        EpochInfo storage ep = epochs[c.epochId];
        if (block.timestamp <= ep.endTime + GRACE_PERIOD) revert AegisDisputeWindowActive();
        if (block.timestamp > ep.endTime + GRACE_PERIOD + DISPUTE_WINDOW) revert AegisDisputeWindowClosed();
        if (c.disputed || c.settled) revert AegisClaimDisputed();

        c.disputed = true;
        if (c.vaultPortion > 0) {
            encumberedLiquidity -= c.vaultPortion;
            ep.totalValidClaimed -= c.vaultPortion;
            ep.totalSlashedDisputed += c.vaultPortion;
        }
        protocolReserve += c.bondSlashed;
        c.bondSlashed = 0;
        emit ClaimDisputedAndSlashed(claimId, msg.sender);
    }

    function finalizeEpoch(uint256 epochId) external {
        EpochInfo storage ep = epochs[epochId];
        if (block.timestamp <= ep.endTime + GRACE_PERIOD + DISPUTE_WINDOW) revert AegisEpochNotReadyForFinalization();
        require(!ep.finalized, "Vault: already finalized");
        ep.finalized = true;
        emit EpochFinalized(epochId, ep.totalValidClaimed, ep.maxCapAmount);
    }

    function settleClaim(uint256 claimId) external whenNotPaused {
        Claim storage c = claims[claimId];
        if (c.settled) revert AegisClaimAlreadySettled();
        if (c.disputed) revert AegisClaimDisputed();
        EpochInfo storage ep = epochs[c.epochId];
        if (!ep.finalized) revert AegisEpochNotFinalized();

        c.settled = true;
        uint256 vaultPayout = 0;
        if (c.vaultPortion > 0) {
            encumberedLiquidity -= c.vaultPortion;
            vaultPayout = ep.totalValidClaimed <= ep.maxCapAmount
                ? c.vaultPortion
                : (c.vaultPortion * ep.maxCapAmount) / ep.totalValidClaimed;

            if (protocolReserve >= vaultPayout) {
                protocolReserve -= vaultPayout;
            } else {
                uint256 lpHit = vaultPayout - protocolReserve;
                protocolReserve = 0;
                totalLpAssets -= lpHit;
            }
        }

        uint256 totalPayout = c.bondSlashed + vaultPayout;
        if (totalPayout > 0) require(usdc.transfer(c.claimant, totalPayout), "Vault: payout transfer failed");
        emit ClaimSettled(claimId, c.claimant, totalPayout);
    }

    function availableTVL() public view returns (uint256) {
        uint256 gross = totalLpAssets + protocolReserve;
        return gross > encumberedLiquidity ? gross - encumberedLiquidity : 0;
    }

    function _rollEpochIfNeeded() internal {
        while (block.timestamp >= epochs[currentEpoch].endTime) {
            uint256 nextEp = currentEpoch + 1;
            uint256 nextStart = epochs[currentEpoch].endTime;
            uint256 avail = availableTVL();
            epochs[nextEp] = EpochInfo(nextStart, nextStart + EPOCH_DURATION, avail, (avail * MAX_EPOCH_CAP_BPS) / BPS_DENOMINATOR, 0, 0, false);
            currentEpoch = nextEp;
            currentEpochStart = nextStart;
        }
    }
}
