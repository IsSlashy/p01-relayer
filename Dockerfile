# P-01 ZK Relayer Service
# Multi-stage build: Rust native Groth16 prover + Node.js relayer
# ~10x faster proof generation vs snarkjs-only

# =============================================================================
# Stage 1: Build Rust native Groth16 prover
# =============================================================================
FROM rust:latest AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy prover source
COPY prover/Cargo.toml prover/Cargo.lock* ./
COPY prover/src/ ./src/

# Build release binary
# __rust_probestack stub provided via global_asm! in main.rs for wasmer compat
RUN cargo build --release && ls -la target/release/p01-prover

# =============================================================================
# Stage 2: Node.js relayer + Rust prover binary
# =============================================================================
FROM node:20-slim

# Install runtime dependencies for the Rust binary
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm

# Copy package files
COPY package.json pnpm-lock.yaml* ./

# Install dependencies
RUN pnpm install --frozen-lockfile || pnpm install

# Copy source code
COPY src/ ./src/
COPY tsconfig.json ./

# Copy circuit files — transfer (shielded pool)
COPY circuits/transfer.wasm ./circuits/transfer.wasm
COPY circuits/transfer_final.zkey ./circuits/transfer_final.zkey
COPY circuits/verification_key.json ./circuits/verification_key.json
COPY circuits/transfer.r1cs ./circuits/transfer.r1cs

# Copy circuit files — zkSPL (confidential balances)
COPY circuits/confidential_balance.wasm ./circuits/confidential_balance.wasm
COPY circuits/confidential_balance_final.zkey ./circuits/confidential_balance_final.zkey
COPY circuits/confidential_balance.r1cs ./circuits/confidential_balance.r1cs
COPY circuits/balance_proof.wasm ./circuits/balance_proof.wasm
COPY circuits/balance_proof_final.zkey ./circuits/balance_proof_final.zkey
COPY circuits/balance_proof.r1cs ./circuits/balance_proof.r1cs
# Verification keys for snarkjs off-chain verification
COPY circuits/confidential_balance_vk.json ./circuits/confidential_balance_vk.json
COPY circuits/balance_proof_vk.json ./circuits/balance_proof_vk.json

# Build TypeScript
RUN pnpm build

# Copy Rust prover binary from builder stage
COPY --from=rust-builder /build/target/release/p01-prover /usr/local/bin/p01-prover

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Environment variables
ENV PORT=8080
ENV PROVER_PORT=3001
ENV WASM_PATH=/app/circuits/transfer.wasm
ENV ZKEY_PATH=/app/circuits/transfer_final.zkey
ENV VERIFICATION_KEY_PATH=/app/circuits/verification_key.json
ENV CIRCUIT_WASM_PATH=/app/circuits/transfer.wasm
ENV CIRCUIT_R1CS_PATH=/app/circuits/transfer.r1cs
ENV CIRCUIT_ZKEY_PATH=/app/circuits/transfer_final.zkey
ENV RUST_PROVER_URL=http://localhost:3001
ENV SOLANA_RPC_URL=https://api.devnet.solana.com
# zkSPL circuit paths for Rust prover
ENV ZKSPL_WASM_PATH=/app/circuits/confidential_balance.wasm
ENV ZKSPL_R1CS_PATH=/app/circuits/confidential_balance.r1cs
ENV ZKSPL_ZKEY_PATH=/app/circuits/confidential_balance_final.zkey
ENV BALANCE_PROOF_WASM_PATH=/app/circuits/balance_proof.wasm
ENV BALANCE_PROOF_R1CS_PATH=/app/circuits/balance_proof.r1cs
ENV BALANCE_PROOF_ZKEY_PATH=/app/circuits/balance_proof_final.zkey
ENV ZKSPL_VK_PATH=/app/circuits/confidential_balance_vk.json
ENV BALANCE_PROOF_VK_PATH=/app/circuits/balance_proof_vk.json

EXPOSE 8080

CMD ["/app/entrypoint.sh"]
