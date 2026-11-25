// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Host Prover (v5.2 Chain-Bound)
use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolValue};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};
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
        uint256 boundChainId;
        address boundRegistry;
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(NITRO_VERIFIER_ELF);
    println!("NITRO_VKEY={}", vk.bytes32());

    if std::env::var("PRINT_VKEY_ONLY").as_deref() == Ok("true") {
        return;
    }

    let attestation_path = std::env::var("NITRO_ATTESTATION_PATH")
        .expect("Set NITRO_ATTESTATION_PATH to genuine /dev/nsm CBOR attestation file");
    let cose_bytes = fs::read(&attestation_path)
        .unwrap_or_else(|_| panic!("Failed to read Nitro CBOR attestation at {}", attestation_path));

    let pub_key_hex = std::env::var("ENCLAVE_PUBKEY")
        .expect("Set ENCLAVE_PUBKEY (20-byte hex address from Nitro Enclave)");
    let pub_key_bytes: [u8; 20] = hex::decode(pub_key_hex.trim_start_matches("0x"))
        .expect("Invalid ENCLAVE_PUBKEY hex")
        .try_into()
        .expect("ENCLAVE_PUBKEY must be 20 bytes");

    let chain_id: u64 = std::env::var("BOUND_CHAIN_ID")
        .expect("Set BOUND_CHAIN_ID (e.g. 84532 for Base Sepolia or 8453 for Base)")
        .parse()
        .expect("Invalid BOUND_CHAIN_ID");
    let chain_id_bytes: [u8; 32] = U256::from(chain_id).to_be_bytes();

    let registry_hex = std::env::var("BOUND_REGISTRY_ADDRESS")
        .expect("Set BOUND_REGISTRY_ADDRESS (deployed AegisSessionRegistry address)");
    let registry_bytes: [u8; 20] = hex::decode(registry_hex.trim_start_matches("0x"))
        .expect("Invalid BOUND_REGISTRY_ADDRESS hex")
        .try_into()
        .expect("BOUND_REGISTRY_ADDRESS must be 20 bytes");

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(cose_bytes);
    stdin.write(&pub_key_bytes);
    stdin.write(&chain_id_bytes);
    stdin.write(&registry_bytes);

    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("SP1 Groth16 proving failed");

    client
        .verify(&proof, &vk)
        .expect("Local SP1 Groth16 proof verification failed");

    let decoded = AttestationPublicValues::abi_decode(proof.public_values.as_slice(), true)
        .expect("Failed to decode 256-byte Solidity AttestationPublicValues");

    assert_eq!(decoded.pubKeyEnclave, Address::from(pub_key_bytes));
    assert_eq!(decoded.boundRegistry, Address::from(registry_bytes));

    println!("VERIFIED_ENCLAVE_SIGNER={}", decoded.pubKeyEnclave);
    println!("VERIFIED_PCR0=0x{}", hex::encode(decoded.pcr0));
    println!("VERIFIED_CERT_SERIAL=0x{}", hex::encode(decoded.certSerial));
    println!("VERIFIED_ATTESTATION_TS={}", decoded.attestationTimestamp);
    println!("PUBLIC_VALUES=0x{}", hex::encode(proof.public_values.as_slice()));
    println!("PROOF_BYTES=0x{}", hex::encode(proof.bytes()));
}
