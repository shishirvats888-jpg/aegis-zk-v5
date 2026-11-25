// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Nitro Verifier (v5.2 Full P-384 Root-of-Trust)
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use ciborium::value::Value;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

// Official AWS Nitro Enclaves Root-G1 Certificate SHA-256 Fingerprint
const AWS_NITRO_ROOT_G1_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef,
    0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0,
    0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

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

pub fn main() {
    // 1. Read genuine AWS Nitro Enclave COSE_Sign1 CBOR bytes & enclave signer address
    let cose_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let pub_key_enclave: [u8; 20] = sp1_zkvm::io::read();

    // 2. Parse outer COSE_Sign1 CBOR array: [protected, unprotected, payload, signature]
    let outer: Value = ciborium::de::from_reader(&cose_bytes[..])
        .expect("AEGIS_SP1: invalid outer COSE CBOR");
    let cose_arr = match outer {
        Value::Array(arr) if arr.len() == 4 => arr,
        Value::Tag(_, inner) => match *inner {
            Value::Array(arr) if arr.len() == 4 => arr,
            _ => panic!("AEGIS_SP1: tagged COSE_Sign1 must be a 4-element array"),
        },
        _ => panic!("AEGIS_SP1: outer COSE_Sign1 must be a 4-element array"),
    };

    let protected_bytes = match &cose_arr {
        Value::Bytes(b) => b.clone(),
        _ => panic!("AEGIS_SP1: COSE protected header must be bytes"),
    };
    let payload_bytes = match &cose_arr {
        Value::Bytes(b) => b.clone(),
        _ => panic!("AEGIS_SP1: COSE payload must be bytes"),
    };
    let cose_sig_bytes = match &cose_arr {
        Value::Bytes(b) => b.clone(),
        _ => panic!("AEGIS_SP1: COSE signature must be bytes"),
    };

    // 3. Parse AWS Nitro Attestation Document payload & enforce canonical CBOR map ordering
    let payload_val: Value = ciborium::de::from_reader(&payload_bytes[..])
        .expect("AEGIS_SP1: invalid Nitro attestation CBOR payload");
    assert_canonical_cbor(&payload_val);

    let entries = match payload_val {
        Value::Map(m) => m,
        _ => panic!("AEGIS_SP1: Nitro payload must be a CBOR map"),
    };

    let mut pcr0_opt: Option<[u8; 32]> = None;
    let mut timestamp_opt: Option<u64> = None;
    let mut leaf_der_opt: Option<Vec<u8>> = None;
    let mut cabundle_opt: Option<Vec<Vec<u8>>> = None;

    for (k, v) in entries {
        if let Value::Text(key_str) = k {
            match key_str.as_str() {
                "timestamp" => {
                    if let Value::Integer(ts_int) = v {
                        let ts_ms: u64 = ts_int
                            .try_into()
                            .expect("AEGIS_SP1: negative attestation timestamp");
                        timestamp_opt = Some(ts_ms / 1000);
                    }
                }
                "pcrs" => {
                    if let Value::Map(pcr_map) = v {
                        for (pk, pv) in pcr_map {
                            if let (Value::Integer(idx), Value::Bytes(pcr_bytes)) = (pk, pv) {
                                let idx_u8: u8 = idx.try_into().unwrap_or(255);
                                if idx_u8 == 0 {
                                    assert!(pcr_bytes.len() >= 32, "AEGIS_SP1: PCR0 < 32 bytes");
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&pcr_bytes[..32]);
                                    pcr0_opt = Some(arr);
                                }
                            }
                        }
                    }
                }
                "certificate" => {
                    if let Value::Bytes(der) = v {
                        leaf_der_opt = Some(der);
                    }
                }
                "cabundle" => {
                    if let Value::Array(arr) = v {
                        let mut chain = Vec::with_capacity(arr.len());
                        for item in arr {
                            if let Value::Bytes(der) = item {
                                chain.push(der);
                            }
                        }
                        cabundle_opt = Some(chain);
                    }
                }
                _ => {}
            }
        }
    }

    let pcr0 = pcr0_opt.expect("AEGIS_SP1: missing pcrs in Nitro attestation");
    let attestation_timestamp =
        timestamp_opt.expect("AEGIS_SP1: missing timestamp in Nitro attestation");
    let leaf_der = leaf_der_opt.expect("AEGIS_SP1: missing leaf X.509 certificate");
    let cabundle = cabundle_opt.expect("AEGIS_SP1: missing cabundle in Nitro attestation");
    assert!(!cabundle.is_empty(), "AEGIS_SP1: empty cabundle");

    // 4. Verify AWS Nitro Root-G1 CA fingerprint & walk X.509 signature chain to leaf certificate
    let root_hash = Sha256::digest(&cabundle);
    assert_eq!(
        root_hash.as_slice(),
        &AWS_NITRO_ROOT_G1_SHA256,
        "AEGIS_SP1: cabundle does not match official AWS Nitro Root-G1 CA"
    );

    let mut min_not_before: u64 = 0;
    let mut max_not_after: u64 = u64::MAX;

    let (_, root_cert) =
        X509Certificate::from_der(&cabundle).expect("AEGIS_SP1: invalid root DER");
    update_validity_bounds(&root_cert, &mut min_not_before, &mut max_not_after);
    let mut current_issuer_vk = VerifyingKey::from_sec1_bytes(
        root_cert.public_key().subject_public_key.data.as_ref(),
    )
    .expect("AEGIS_SP1: invalid root P-384 public key");

    for intermediate_der in cabundle.iter().skip(1) {
        let (_, cert) =
            X509Certificate::from_der(intermediate_der).expect("AEGIS_SP1: invalid intermediate DER");
        verify_x509_p384_signature(&cert, &current_issuer_vk);
        update_validity_bounds(&cert, &mut min_not_before, &mut max_not_after);
        current_issuer_vk = VerifyingKey::from_sec1_bytes(
            cert.public_key().subject_public_key.data.as_ref(),
        )
        .expect("AEGIS_SP1: invalid intermediate P-384 public key");
    }

    let (_, leaf_cert) =
        X509Certificate::from_der(&leaf_der).expect("AEGIS_SP1: invalid leaf X.509 DER");
    verify_x509_p384_signature(&leaf_cert, &current_issuer_vk);
    update_validity_bounds(&leaf_cert, &mut min_not_before, &mut max_not_after);

    let leaf_vk = VerifyingKey::from_sec1_bytes(
        leaf_cert.public_key().subject_public_key.data.as_ref(),
    )
    .expect("AEGIS_SP1: invalid leaf P-384 public key");

    // 5. Verify RFC 8152 COSE_Sign1 Sig_structure ECDSA P-384 signature using verified leaf key
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bytes),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload_bytes),
    ]);
    let mut to_be_signed = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut to_be_signed)
        .expect("AEGIS_SP1: failed to serialize COSE Sig_structure");

    let cose_sig =
        Signature::from_slice(&cose_sig_bytes).expect("AEGIS_SP1: invalid COSE P-384 signature");
    leaf_vk
        .verify(&to_be_signed, &cose_sig)
        .expect("AEGIS_SP1: COSE_Sign1 P-384 signature verification failed");

    // 6. Commit 192-byte Solidity ABI-encoded publicValues matching AegisSessionRegistry.sol
    let serial_hash = Sha256::digest(leaf_cert.raw_serial());
    let mut cert_serial = [0u8; 32];
    cert_serial.copy_from_slice(&serial_hash);

    let public_values = AttestationPublicValues {
        pubKeyEnclave: pub_key_enclave.into(),
        pcr0: pcr0.into(),
        certSerial: cert_serial.into(),
        attestationTimestamp: attestation_timestamp,
        minCertNotBefore: min_not_before,
        maxCertNotAfter: max_not_after,
    };

    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}

fn verify_x509_p384_signature(cert: &X509Certificate<'_>, issuer_vk: &VerifyingKey) {
    let der_sig = cert.signature_value.data.as_ref();
    let sig = Signature::from_der(der_sig)
        .expect("AEGIS_SP1: X.509 signature is not valid DER ECDSA P-384");
    issuer_vk
        .verify(cert.tbs_certificate.as_ref(), &sig)
        .expect("AEGIS_SP1: X.509 certificate chain signature verification failed");
}

fn update_validity_bounds(cert: &X509Certificate<'_>, min_nb: &mut u64, max_na: &mut u64) {
    let nb = u64::try_from(cert.validity().not_before.timestamp())
        .expect("AEGIS_SP1: invalid cert not_before");
    let na = u64::try_from(cert.validity().not_after.timestamp())
        .expect("AEGIS_SP1: invalid cert not_after");
    if nb > *min_nb {
        *min_nb = nb;
    }
    if na < *max_na {
        *max_na = na;
    }
}

fn assert_canonical_cbor(val: &Value) {
    match val {
        Value::Map(entries) => {
            let mut prev: Option<Vec<u8>> = None;
            for (k, v) in entries {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(k, &mut buf)
                    .expect("AEGIS_SP1: CBOR key serialize failed");
                if let Some(ref p) = prev {
                    assert!(
                        p.as_slice() < buf.as_slice(),
                        "AEGIS_SP1: duplicate or unsorted CBOR key"
                    );
                }
                prev = Some(buf);
                assert_canonical_cbor(v);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_canonical_cbor(item);
            }
        }
        _ => {}
    }
}
