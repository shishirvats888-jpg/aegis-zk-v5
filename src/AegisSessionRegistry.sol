// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Full SHA-384 Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

interface ISecurityCouncil {
    function globalPaused() external view returns (bool);
}

contract AegisSessionRegistry {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable nitroVerifierVKey;
    address public immutable governanceTimelock;
    ISecurityCouncil public immutable securityCouncil;

    bytes32 public latestApprovedPCR0High;
    bytes16 public latestApprovedPCR0Low;
    uint256 public constant SESSION_TTL = 24 hours;
    uint256 public constant MAX_ATTESTATION_AGE = 10 minutes;

    struct EnclaveSession {
        uint64 registeredAt;
        uint64 expiresAt;
        bytes32 pcr0High;
        bytes16 pcr0Low;
        bytes32 certSerial;
        bool revoked;
    }

    mapping(address => EnclaveSession) public sessions;
    mapping(bytes32 => bool) public usedCertSerials;
    mapping(bytes32 => bool) public revokedCertSerials;

    event EnclaveSessionRegistered(
        address indexed enclaveSigner,
        bytes32 indexed pcr0High,
        bytes16 pcr0Low,
        bytes32 indexed certSerial,
        uint64 expiresAt
    );
    event EnclaveSessionRevoked(address indexed enclaveSigner, bytes32 indexed certSerial, string reason);
    event ApprovedPCR0Updated(bytes32 oldPCR0High, bytes16 oldPCR0Low, bytes32 newPCR0High, bytes16 newPCR0Low);

    error AegisProtocolPaused();
    error AegisUnauthorized();
    error AegisInvalidPCR0(bytes32 providedHigh, bytes16 providedLow, bytes32 expectedHigh, bytes16 expectedLow);
    error AegisZeroPCR0Forbidden();
    error AegisInvalidChainOrRegistryBinding(uint256 providedChainId, address providedRegistry);
    error AegisCertSerialReplayOrRevoked(bytes32 certSerial);
    error AegisStaleAttestation(uint256 attestationTs, uint256 blockTs);
    error AegisCertificateExpiredOrPremature(uint256 currentTs, uint256 notBefore, uint256 notAfter);
    error AegisSessionAlreadyActive(address signer);

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock) revert AegisUnauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) revert AegisProtocolPaused();
        _;
    }

    constructor(
        address _sp1Verifier,
        bytes32 _nitroVerifierVKey,
        bytes32 _initialApprovedPCR0High,
        bytes16 _initialApprovedPCR0Low,
        address _governanceTimelock,
        address _securityCouncil
    ) {
        if (_initialApprovedPCR0High == bytes32(0) && _initialApprovedPCR0Low == bytes16(0)) {
            revert AegisZeroPCR0Forbidden();
        }
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        nitroVerifierVKey = _nitroVerifierVKey;
        latestApprovedPCR0High = _initialApprovedPCR0High;
        latestApprovedPCR0Low = _initialApprovedPCR0Low;
        governanceTimelock = _governanceTimelock;
        securityCouncil = ISecurityCouncil(_securityCouncil);
    }

    function registerEnclaveSession(bytes calldata publicValues, bytes calldata proofBytes) external whenNotPaused {
        sp1Verifier.verifyProof(nitroVerifierVKey, publicValues, proofBytes);

        (
            address pubKeyEnclave,
            bytes32 pcr0High,
            bytes16 pcr0Low,
            bytes32 certSerial,
            uint64 attestationTimestamp,
            uint64 minCertNotBefore,
            uint64 maxCertNotAfter,
            uint256 boundChainId,
            address boundRegistry
        ) = abi.decode(
            publicValues,
            (address, bytes32, bytes16, bytes32, uint64, uint64, uint64, uint256, address)
        );

        if (boundChainId != block.chainid || boundRegistry != address(this)) {
            revert AegisInvalidChainOrRegistryBinding(boundChainId, boundRegistry);
        }
        if (
            (pcr0High == bytes32(0) && pcr0Low == bytes16(0)) ||
            (latestApprovedPCR0High == bytes32(0) && latestApprovedPCR0Low == bytes16(0))
        ) {
            revert AegisZeroPCR0Forbidden();
        }
        if (pcr0High != latestApprovedPCR0High || pcr0Low != latestApprovedPCR0Low) {
            revert AegisInvalidPCR0(pcr0High, pcr0Low, latestApprovedPCR0High, latestApprovedPCR0Low);
        }
        if (usedCertSerials[certSerial] || revokedCertSerials[certSerial]) revert AegisCertSerialReplayOrRevoked(certSerial);
        if (attestationTimestamp > block.timestamp + 60 || (block.timestamp > attestationTimestamp && block.timestamp - attestationTimestamp > MAX_ATTESTATION_AGE)) {
            revert AegisStaleAttestation(attestationTimestamp, block.timestamp);
        }
        if (block.timestamp < minCertNotBefore || block.timestamp > maxCertNotAfter) {
            revert AegisCertificateExpiredOrPremature(block.timestamp, minCertNotBefore, maxCertNotAfter);
        }

        EnclaveSession storage existing = sessions[pubKeyEnclave];
        if (existing.expiresAt > block.timestamp && !existing.revoked) revert AegisSessionAlreadyActive(pubKeyEnclave);

        usedCertSerials[certSerial] = true;
        uint64 exp = uint64(block.timestamp + SESSION_TTL);
        sessions[pubKeyEnclave] = EnclaveSession(uint64(block.timestamp), exp, pcr0High, pcr0Low, certSerial, false);

        emit EnclaveSessionRegistered(pubKeyEnclave, pcr0High, pcr0Low, certSerial, exp);
    }

    function emergencyRevokeSession(address enclaveSigner, string calldata reason) external onlyGovernance {
        EnclaveSession storage s = sessions[enclaveSigner];
        s.revoked = true;
        revokedCertSerials[s.certSerial] = true;
        emit EnclaveSessionRevoked(enclaveSigner, s.certSerial, reason);
    }

    function updateApprovedPCR0(bytes32 newPCR0High, bytes16 newPCR0Low) external onlyGovernance {
        if (newPCR0High == bytes32(0) && newPCR0Low == bytes16(0)) revert AegisZeroPCR0Forbidden();
        bytes32 oldHigh = latestApprovedPCR0High;
        bytes16 oldLow = latestApprovedPCR0Low;
        latestApprovedPCR0High = newPCR0High;
        latestApprovedPCR0Low = newPCR0Low;
        emit ApprovedPCR0Updated(oldHigh, oldLow, newPCR0High, newPCR0Low);
    }

    function isValidEnclaveSigner(address signer) external view returns (bool) {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) return false;
        EnclaveSession memory s = sessions[signer];
        return (
            s.registeredAt > 0 &&
            !s.revoked &&
            !revokedCertSerials[s.certSerial] &&
            block.timestamp <= s.expiresAt &&
            (s.pcr0High != bytes32(0) || s.pcr0Low != bytes16(0)) &&
            s.pcr0High == latestApprovedPCR0High &&
            s.pcr0Low == latestApprovedPCR0Low
        );
    }
}
