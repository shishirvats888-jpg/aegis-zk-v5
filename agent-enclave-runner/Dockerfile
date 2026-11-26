# Created & Architected by Shishir Vats | AEGIS-ZK AWS Nitro Enclave Image (v5.2 Zero-Trust)
FROM rust:1.82-bookworm AS nsm-builder
WORKDIR /build
COPY nsm-attestation/ ./
RUN cargo build --release

FROM node:20-bookworm-slim
WORKDIR /opt/aegis
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl socat && rm -rf /var/lib/apt/lists/*
COPY --from=nsm-builder /build/target/release/aegis-nsm-attestation /usr/local/bin/aegis-nsm-attestation
COPY package.json server.ts entrypoint.sh ./
RUN chmod +x /opt/aegis/entrypoint.sh
RUN npm install --omit=dev
RUN mkdir -p /opt/aegis/models && \
    curl -fSL -o /opt/aegis/models/qwen2.5-1.5b-instruct-q4_k_m.gguf \
    https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf
CMD ["/opt/aegis/entrypoint.sh"]
