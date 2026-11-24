// Created & Architected by Shishir Vats | AEGIS-ZK (v5.2 Zero-Trust Edition)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

interface ISecurityCouncilPause {
    function globalPaused() external view returns (bool);
}

contract AegisSessionRegistry {
    string public constant PROTOCOL_AUTHOR = "Shishir Vats";
    string public constant PROTOCOL_VERSION = "AEGIS-ZK-v5.2-SHISHIR-VATS";

    ISP1Verifier public immutable sp1Verifier;
    bytes32 public immutable nitroVerifierVKey;
    ISecurityCouncilPause public immutable securityCouncil;
    address public governanceTimelock;

    bytes32 public latestApprovedPCR0;
    uint256 public constant KEY_TTL = 24 hours;
    uint256 public constant MAX_TIMESTAMP_DRIFT = 1 hours;

    struct EnclaveSession {
        uint64 registeredAt;
        uint64 expiresAt;
        bytes32 pcr0;
        bytes32 certSerial;
        bool revoked;
    }

    mapping(address => EnclaveSession) public sessions;
    mapping(bytes32 => bool) public revokedCertSerials;
    mapping(bytes32 => bool) public usedAttestationHashes;

    event EnclaveSessionRegistered(address indexed enclaveSigner, bytes32 indexed pcr0, bytes32 certSerial, uint64 expiresAt);
    event EnclaveSessionRevoked(address indexed enclaveSigner);
    event ApprovedPCR0Updated(bytes32 indexed oldPCR0, bytes32 indexed newPCR0);
    event CertSerialRevoked(bytes32 indexed certSerial);

    error AegisProtocolPaused();
    error AegisUnauthorized();
    error AegisInvalidPCR0(bytes32 provided, bytes32 expected);
    error AegisRevokedCertificate(bytes32 certSerial);
    error AegisCertificateExpiredOrNotYetValid(uint256 nowTs, uint64 notBefore, uint64 notAfter);
    error AegisAttestationTimestampDrift(uint256 nowTs, uint64 attestationTs);
    error AegisAttestationAlreadyUsed(bytes32 attestationHash);
    error AegisZeroSigner();

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock) revert AegisUnauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) revert AegisProtocolPaused();
        _;
    }

    constructor(address _sp1Verifier, bytes32 _nitroVerifierVKey, bytes32 _initialApprovedPCR0, address _governanceTimelock, address _securityCouncil) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        nitroVerifierVKey = _nitroVerifierVKey;
        latestApprovedPCR0 = _initialApprovedPCR0;
        governanceTimelock = _governanceTimelock;
        securityCouncil = ISecurityCouncilPause(_securityCouncil);
    }

    function registerEnclaveSession(bytes calldata publicValues, bytes calldata proofBytes) external whenNotPaused {
        bytes32 attHash = keccak256(publicValues);
        if (usedAttestationHashes[attHash]) revert AegisAttestationAlreadyUsed(attHash);
        usedAttestationHashes[attHash] = true;

        sp1Verifier.verifyProof(nitroVerifierVKey, publicValues, proofBytes);

        (address pubKeyEnclave, bytes32 pcr0, bytes32 certSerial, uint64 attestationTimestamp, uint64 minCertNotBefore, uint64 maxCertNotAfter) =
            abi.decode(publicValues, (address, bytes32, bytes32, uint64, uint64, uint64));

        if (pubKeyEnclave == address(0)) revert AegisZeroSigner();
        if (pcr0 != latestApprovedPCR0) revert AegisInvalidPCR0(pcr0, latestApprovedPCR0);
        if (revokedCertSerials[certSerial]) revert AegisRevokedCertificate(certSerial);
        if (block.timestamp < minCertNotBefore || block.timestamp > maxCertNotAfter) {
            revert AegisCertificateExpiredOrNotYetValid(block.timestamp, minCertNotBefore, maxCertNotAfter);
        }

        uint256 drift = block.timestamp >= attestationTimestamp ? block.timestamp - attestationTimestamp : attestationTimestamp - block.timestamp;
        if (drift > MAX_TIMESTAMP_DRIFT) revert AegisAttestationTimestampDrift(block.timestamp, attestationTimestamp);

        uint64 expiresAt = uint64(block.timestamp + KEY_TTL);
        sessions[pubKeyEnclave] = EnclaveSession(uint64(block.timestamp), expiresAt, pcr0, certSerial, false);
        emit EnclaveSessionRegistered(pubKeyEnclave, pcr0, certSerial, expiresAt);
    }

    function isValidEnclaveSigner(address signer) external view returns (bool) {
        if (address(securityCouncil) != address(0) && securityCouncil.globalPaused()) return false;
        EnclaveSession memory s = sessions[signer];
        if (s.registeredAt == 0 || s.revoked || block.timestamp > s.expiresAt) return false;
        if (s.pcr0 != latestApprovedPCR0 || revokedCertSerials[s.certSerial]) return false;
        return true;
    }

    function updateApprovedPCR0(bytes32 newPCR0) external onlyGovernance {
        bytes32 old = latestApprovedPCR0;
        latestApprovedPCR0 = newPCR0;
        emit ApprovedPCR0Updated(old, newPCR0);
    }

    function revokeCertSerial(bytes32 certSerial) external onlyGovernance {
        revokedCertSerials[certSerial] = true;
        emit CertSerialRevoked(certSerial);
    }

    function emergencyRevokeSigner(address enclaveSigner) external onlyGovernance {
        sessions[enclaveSigner].revoked = true;
        emit EnclaveSessionRevoked(enclaveSigner);
    }
}
