// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAggregatorV3 {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    function decimals() external view returns (uint8);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

interface IWstETH {
    function stEthPerToken() external view returns (uint256);
}

contract AegisOracleGuard {
    address public immutable governanceTimelock;
    IAggregatorV3 public immutable sequencerUptimeFeed;
    uint256 public constant SEQUENCER_GRACE_PERIOD = 1 hours;
    uint256 public constant BPS_DENOMINATOR = 10_000;

    struct FeedConfig {
        address chainlinkFeed;
        address wstEthWrapper;
        uint256 maxStaleness;
        uint256 maxDeviationBps;
        bool enabled;
    }

    mapping(address => FeedConfig) public tokenFeeds;

    event TokenFeedConfigured(address indexed token, address indexed feed, address wstEthWrapper, uint256 maxStaleness, uint256 maxDeviationBps);
    error AegisUnauthorized();
    error AegisSequencerDown();
    error AegisSequencerGracePeriodNotOver(uint256 elapsed, uint256 required);
    error AegisFeedNotConfigured(address token);
    error AegisStaleOraclePrice(address token, uint256 updatedAt, uint256 maxStaleness);
    error AegisInvalidOracleAnswer(address token, int256 answer);
    error AegisPriceDeviationExceeded(address token, uint256 zkTlsPrice, uint256 oraclePrice, uint256 maxBps);

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock) revert AegisUnauthorized();
        _;
    }

    constructor(address _governanceTimelock, address _sequencerUptimeFeed) {
        governanceTimelock = _governanceTimelock;
        sequencerUptimeFeed = IAggregatorV3(_sequencerUptimeFeed);
    }

    function configureTokenFeed(address token, address chainlinkFeed, address wstEthWrapper, uint256 maxStaleness, uint256 maxDeviationBps) external onlyGovernance {
        tokenFeeds[token] = FeedConfig(chainlinkFeed, wstEthWrapper, maxStaleness, maxDeviationBps, true);
        emit TokenFeedConfigured(token, chainlinkFeed, wstEthWrapper, maxStaleness, maxDeviationBps);
    }

    function getValidatedOraclePrice18(address token) public view returns (uint256 price18) {
        if (address(sequencerUptimeFeed) != address(0)) {
            (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
            if (answer != 0) revert AegisSequencerDown();
            if (startedAt == 0 || block.timestamp - startedAt <= SEQUENCER_GRACE_PERIOD) {
                revert AegisSequencerGracePeriodNotOver(startedAt == 0 ? 0 : block.timestamp - startedAt, SEQUENCER_GRACE_PERIOD);
            }
        }
        FeedConfig memory cfg = tokenFeeds[token];
        if (!cfg.enabled || cfg.chainlinkFeed == address(0)) revert AegisFeedNotConfigured(token);

        IAggregatorV3 feed = IAggregatorV3(cfg.chainlinkFeed);
        (uint80 roundId, int256 rawAnswer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        if (rawAnswer <= 0 || answeredInRound < roundId) revert AegisInvalidOracleAnswer(token, rawAnswer);
        if (updatedAt == 0 || block.timestamp - updatedAt > cfg.maxStaleness) revert AegisStaleOraclePrice(token, updatedAt, cfg.maxStaleness);

        uint8 dec = feed.decimals();
        price18 = dec <= 18 ? uint256(rawAnswer) * (10 ** (18 - dec)) : uint256(rawAnswer) / (10 ** (dec - 18));

        if (cfg.wstEthWrapper != address(0)) {
            uint256 stEthPerToken = IWstETH(cfg.wstEthWrapper).stEthPerToken();
            price18 = (price18 * stEthPerToken) / 1e18;
        }
    }

    function assertZkTlsPriceWithinBounds(address token, uint256 zkTlsPrice18) external view returns (uint256 oraclePrice18) {
        oraclePrice18 = getValidatedOraclePrice18(token);
        FeedConfig memory cfg = tokenFeeds[token];
        uint256 diff = zkTlsPrice18 >= oraclePrice18 ? zkTlsPrice18 - oraclePrice18 : oraclePrice18 - zkTlsPrice18;
        uint256 maxAllowedDiff = (oraclePrice18 * cfg.maxDeviationBps) / BPS_DENOMINATOR;
        if (diff > maxAllowedDiff) revert AegisPriceDeviationExceeded(token, zkTlsPrice18, oraclePrice18, cfg.maxDeviationBps);
    }
}
