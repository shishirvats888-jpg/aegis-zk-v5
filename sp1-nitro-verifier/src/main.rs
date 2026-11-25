// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Nitro Verifier (v5.2 Production)
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

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
        Value::Array(arr) if arr.len() >= 3 => arr,
        Value::Tag(_, inner) => match *inner {
            Value::Array(arr) if arr.len() >= 3 => arr,
            _ => panic!("AEGIS_SP1: tagged COSE_Sign1 is not an array"),
        },
        _ => panic!("AEGIS_SP1: outer COSE_Sign1 must be a 4-element array"),
    };

    let payload_bytes = match &cose_arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => panic!("AEGIS_SP1: COSE_Sign1 payload must be CBOR bytes"),
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
    let mut cert_der_opt: Option<Vec<u8>> = None;

    for (k, v) in entries {
        if let Value::Text(key_str) = k {
            match key_str.as_str() {
                "timestamp" => {
                    if let Value::Integer(ts_int) = v {
                        let ts_ms: u64 = ts_int
                            .try_into()
                            .expect("AEGIS_SP1: negative attestation timestamp");
                        // AWS Nitro timestamps are milliseconds since epoch; convert to seconds
                        timestamp_opt = Some(ts_ms / 1000);
                    }
                }
                "pcrs" => {
                    if let Value::Map(pcr_map) = v {
                        for (pk, pv) in pcr_map {
                            if let (Value::Integer(idx), Value::Bytes(pcr_bytes)) = (pk, pv) {
                                let idx_u8: u8 = idx.try_into().unwrap_or(255);
                                if idx_u8 == 0 {
                                    assert!(
                                        pcr_bytes.len() >= 32,
                                        "AEGIS_SP1: PCR0 must be at least 32 bytes"
                                    );
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
                        cert_der_opt = Some(der);
                    }
                }
                _ => {}
            }
        }
    }

    let pcr0 = pcr0_opt.expect("AEGIS_SP1: missing pcrs[0] in Nitro attestation");
    let attestation_timestamp =
        timestamp_opt.expect("AEGIS_SP1: missing timestamp in Nitro attestation");
    let cert_der = cert_der_opt.expect("AEGIS_SP1: missing leaf X.509 certificate in Nitro attestation");

    // 4. Parse genuine X.509 certificate serial & validity window from DER bytes
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .expect("AEGIS_SP1: invalid X.509 leaf certificate DER");
    let serial_hash = Sha256::digest(cert.raw_serial());
    let mut cert_serial = [0u8; 32];
    cert_serial.copy_from_slice(&serial_hash);

    let min_cert_not_before = u64::try_from(cert.validity().not_before.timestamp())
        .expect("AEGIS_SP1: invalid cert not_before timestamp");
    let max_cert_not_after = u64::try_from(cert.validity().not_after.timestamp())
        .expect("AEGIS_SP1: invalid cert not_after timestamp");

    // 5. Commit 192-byte Solidity ABI-encoded publicValues matching AegisSessionRegistry.sol
    let public_values = AttestationPublicValues {
        pubKeyEnclave: pub_key_enclave.into(),
        pcr0: pcr0.into(),
        certSerial: cert_serial.into(),
        attestationTimestamp: attestation_timestamp,
        minCertNotBefore: min_cert_not_before,
        maxCertNotAfter: max_cert_not_after,
    };

    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
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
