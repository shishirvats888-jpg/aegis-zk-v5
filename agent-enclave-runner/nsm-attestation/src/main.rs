// Created & Architected by Shishir Vats | AEGIS-ZK AWS Nitro /dev/nsm Hardware Attestation Generator
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("Usage: aegis-nsm-attestation <72-byte-user-data-hex> <output-cbor-path>");
    }

    let user_data_bytes = hex::decode(args[1].trim_start_matches("0x"))
        .expect("Invalid 72-byte user_data hex");
    assert_eq!(
        user_data_bytes.len(),
        72,
        "user_data must be exactly 72 bytes: enclaveSigner(20) || chainId(32) || registry(20)"
    );

    let fd = nsm_init();
    assert!(fd >= 0, "Failed to open /dev/nsm — must execute inside an AWS Nitro Enclave");

    let request = Request::Attestation {
        user_data: Some(ByteBuf::from(user_data_bytes)),
        nonce: None,
        public_key: None,
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => {
            fs::write(&args[2], &document)
                .unwrap_or_else(|e| panic!("Failed to write CBOR attestation to {}: {}", args[2], e));
            println!("AEGIS_NSM_ATTESTATION_WRITTEN={} bytes={}", args[2], document.len());
        }
        other => panic!("Unexpected /dev/nsm response: {:?}", other),
    }
}
