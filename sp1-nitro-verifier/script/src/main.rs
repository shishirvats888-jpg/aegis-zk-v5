// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Host Prover
use alloy_sol_types::sol;
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
    let cose_bytes = fs::read("nitro_attestation.cbor")
        .expect("Missing nitro_attestation.cbor from AWS Nitro Enclave /dev/nsm");
    let pub_key_hex = std::env::var("ENCLAVE_PUBKEY")
        .expect("Set ENCLAVE_PUBKEY (20-byte hex address)");
    let pub_key_bytes: [u8; 20] = hex::decode(pub_key_hex.trim_start_matches("0x"))
        .expect("Invalid ENCLAVE_PUBKEY hex")
        .try_into()
        .expect("ENCLAVE_PUBKEY must be 20 bytes");

    let cert_serial = [0x11u8; 32];
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let min_not_before = now_ts - 3600;
    let max_not_after = now_ts + 86400 * 30;

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(cose_bytes);
    stdin.write(&pub_key_bytes);
    stdin.write(&cert_serial);
    stdin.write(&now_ts);
    stdin.write(&min_not_before);
    stdin.write(&max_not_after);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(NITRO_VERIFIER_ELF);
    let proof = client.prove(&pk, &stdin).groth16().run().expect("SP1 Groth16 proving failed");
    client.verify(&proof, &vk).expect("Local SP1 proof verification failed");

    println!("PUBLIC_VALUES=0x{}", hex::encode(proof.public_values.as_slice()));
    println!("PROOF_BYTES=0x{}", hex::encode(proof.bytes()));
}
