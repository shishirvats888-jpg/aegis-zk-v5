// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Host Prover (v5.2 Zero-Shortcut)
use alloy_sol_types::{sol, SolValue};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::fs;

pub const NITRO_VERIFIER_ELF: &[u8] = include_elf!("aegis-nitro-verifier");

sol! {
    struct AttestationPublicValues {
        address pubKeyEnclave;
        bytes32 pcr0;
        bytes32 certSerial;
        uint64 attestationTimestamp;
        uint64 minCertNotBefore;
        uint64 maxCertNotAfter;
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // 1. Read genuine AWS Nitro Enclave COSE_Sign1 CBOR attestation from /dev/nsm output
    let attestation_path = std::env::var("NITRO_ATTESTATION_PATH")
        .unwrap_or_else(|_| "nitro_attestation.cbor".to_string());
    let cose_bytes = fs::read(&attestation_path)
        .unwrap_or_else(|_| panic!("Missing genuine Nitro CBOR attestation at {}", attestation_path));

    // 2. Read genuine enclave ephemeral secp256k1 signer address
    let pub_key_hex = std::env::var("ENCLAVE_PUBKEY")
        .expect("Set ENCLAVE_PUBKEY (20-byte hex address from Nitro Enclave /health)");
    let pub_key_bytes: [u8; 20] = hex::decode(pub_key_hex.trim_start_matches("0x"))
        .expect("Invalid ENCLAVE_PUBKEY hex")
        .try_into()
        .expect("ENCLAVE_PUBKEY must be 20 bytes");

    // 3. Feed only genuine CBOR attestation & signer address into SP1 zkVM (zero hardcoded metadata)
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(cose_bytes);
    stdin.write(&pub_key_bytes);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(NITRO_VERIFIER_ELF);
    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("SP1 Groth16 proving failed");

    client
        .verify(&proof, &vk)
        .expect("Local SP1 Groth16 proof verification failed");

    let decoded = AttestationPublicValues::abi_decode(proof.public_values.as_slice(), true)
        .expect("Failed to decode 192-byte Solidity AttestationPublicValues");

    println!("VERIFIED_ENCLAVE_SIGNER={}", decoded.pubKeyEnclave);
    println!("VERIFIED_PCR0=0x{}", hex::encode(decoded.pcr0));
    println!("VERIFIED_CERT_SERIAL=0x{}", hex::encode(decoded.certSerial));
    println!("VERIFIED_ATTESTATION_TS={}", decoded.attestationTimestamp);
    println!("PUBLIC_VALUES=0x{}", hex::encode(proof.public_values.as_slice()));
    println!("PROOF_BYTES=0x{}", hex::encode(proof.bytes()));
}
