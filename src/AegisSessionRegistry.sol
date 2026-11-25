// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
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

    bytes32 public latestApprovedPCR0;
    uint256 public constant SESSION_TTL = 24 hours;
    uint256 public constant MAX_ATTESTATION_AGE = 10 minutes;

    struct EnclaveSession {
        uint64 registeredAt;
        uint64 expiresAt;
        bytes32 pcr0;
        bytes32 certSerial;
        bool revoked;
    }

    mapping(address => EnclaveSession) public sessions;
    mapping(bytes32 => bool) public usedCertSerials;
    mapping(bytes32 => bool) public revokedCertSerials;

    event EnclaveSessionRegistered(address indexed enclaveSigner, bytes32 indexed pcr0, bytes32 indexed certSerial, uint64 expiresAt);
    event EnclaveSessionRevoked(address indexed enclaveSigner, bytes32 indexed certSerial, string reason);
    event ApprovedPCR0Updated(bytes32 oldPCR0, bytes32 newPCR0);

    error AegisProtocolPaused();
    error AegisUnauthorized();
    error AegisInvalidPCR0(bytes32 provided, bytes32 expected);
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

    constructor(address _sp1Verifier, bytes32 _nitroVerifierVKey, bytes32 _initialApprovedPCR0, address _governanceTimelock, address _securityCouncil) {
        if (_initialApprovedPCR0 == bytes32(0)) revert AegisZeroPCR0Forbidden();
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        nitroVerifierVKey = _nitroVerifierVKey;
        latestApprovedPCR0 = _initialApprovedPCR0;
        governanceTimelock = _governanceTimelock;
        securityCouncil = ISecurityCouncil(_securityCouncil);
    }

    function registerEnclaveSession(bytes calldata publicValues, bytes calldata proofBytes) external whenNotPaused {
        sp1Verifier.verifyProof(nitroVerifierVKey, publicValues, proofBytes);

        (
            address pubKeyEnclave,
            bytes32 pcr0,
            bytes32 certSerial,
            uint64 attestationTimestamp,
            uint64 minCertNotBefore,
            uint64 maxCertNotAfter,
            uint256 boundChainId,
            address boundRegistry
        ) = abi.decode(publicValues, (address, bytes32, bytes32, uint64, uint64, uint64, uint256, address));

        if (boundChainId != block.chainid || boundRegistry != address(this)) {
            revert AegisInvalidChainOrRegistryBinding(boundChainId, boundRegistry);
        }
        if (pcr0 == bytes32(0) || latestApprovedPCR0 == bytes32(0)) revert AegisZeroPCR0Forbidden();
        if (pcr0 != latestApprovedPCR0) revert AegisInvalidPCR0(pcr0, latestApprovedPCR0);
        if (usedCertSerials[certSerial] || revokedCertSerials[certSerial]) revert AegisCertSerialReplayOrRevoked(certSerial);
        if (attestationTimestamp > block.timestamp + 60 || block.timestamp - attestationTimestamp > MAX_ATTESTATION_AGE) {
            revert AegisStaleAttestation(attestationTimestamp, block.timestamp);
        }
        if (block.timestamp < minCertNotBefore || block.timestamp > maxCertNotAfter) {
            revert AegisCertificateExpiredOrPremature(block.timestamp, minCertNotBefore, maxCertNotAfter);
        }

        EnclaveSession storage existing = sessions[pubKeyEnclave];
        if (existing.expiresAt > block.timestamp && !existing.revoked) revert AegisSessionAlreadyActive(pubKeyEnclave);

        usedCertSerials[certSerial] = true;
        uint64 exp = uint64(block.timestamp + SESSION_TTL);
        sessions[pubKeyEnclave] = EnclaveSession(uint64(block.timestamp), exp, pcr0, certSerial, false);

        emit EnclaveSessionRegistered(pubKeyEnclave, pcr0, certSerial, exp);
    }

    function emergencyRevokeSession(address enclaveSigner, string calldata reason) external onlyGovernance {
        EnclaveSession storage s = sessions[enclaveSigner];
        s.revoked = true;
        revokedCertSerials[s.certSerial] = true;
        emit EnclaveSessionRevoked(enclaveSigner, s.certSerial, reason);
    }

    function updateApprovedPCR0(bytes32 newPCR0) external onlyGovernance {
        if (newPCR0 == bytes32(0)) revert AegisZeroPCR0Forbidden();
        bytes32 old = latestApprovedPCR0;
        latestApprovedPCR0 = newPCR0;
        emit ApprovedPCR0Updated(old, newPCR0);
    }

    function isValidEnclaveSigner(address signer) external view returns (bool) {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) return false;
        EnclaveSession memory s = sessions[signer];
        return (
            s.registeredAt > 0 &&
            !s.revoked &&
            !revokedCertSerials[s.certSerial] &&
            block.timestamp <= s.expiresAt &&
            s.pcr0 != bytes32(0) &&
            s.pcr0 == latestApprovedPCR0
        );
    }
}
