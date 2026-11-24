// Created & Architected by Shishir Vats | AEGIS-ZK SP1 Nitro Verifier
#![no_main]
sp1_zkvm::entrypoint!(main);

use ciborium::value::Value;
use sha2::{Digest, Sha384};

pub fn main() {
    let cose_bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let root: Value = ciborium::de::from_reader(&cose_bytes[..])
        .expect("AEGIS_SP1: invalid CBOR structure");

    // Enforce RFC 8949 Section 4.2.1 Canonical CBOR Map Ordering (zero duplicate keys)
    assert_canonical_cbor(&root);

    let mut hasher = Sha384::new();
    hasher.update(&cose_bytes);
    let digest = hasher.finalize();

    let mut pcr0 = [0u8; 32];
    pcr0.copy_from_slice(&digest[..32]);

    let pub_key_enclave: [u8; 20] = sp1_zkvm::io::read();
    let cert_serial: [u8; 32] = sp1_zkvm::io::read();
    let attestation_timestamp: u64 = sp1_zkvm::io::read();
    let min_cert_not_before: u64 = sp1_zkvm::io::read();
    let max_cert_not_after: u64 = sp1_zkvm::io::read();

    sp1_zkvm::io::commit_slice(&pub_key_enclave);
    sp1_zkvm::io::commit_slice(&pcr0);
    sp1_zkvm::io::commit_slice(&cert_serial);
    sp1_zkvm::io::commit(&attestation_timestamp);
    sp1_zkvm::io::commit(&min_cert_not_before);
    sp1_zkvm::io::commit(&max_cert_not_after);
}

fn assert_canonical_cbor(val: &Value) {
    match val {
        Value::Map(entries) => {
            let mut prev: Option<Vec<u8>> = None;
            for (k, v) in entries {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(k, &mut buf).expect("AEGIS_SP1: key serialize failed");
                if let Some(ref p) = prev {
                    assert!(p.as_slice() < buf.as_slice(), "AEGIS_SP1: duplicate or unsorted CBOR key");
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
