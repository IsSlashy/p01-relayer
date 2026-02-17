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

# Build release binary (optimized: LTO + single codegen unit)
RUN cargo build --release

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

# Copy circuit files
COPY circuits/transfer.wasm ./circuits/transfer.wasm
COPY circuits/transfer_final.zkey ./circuits/transfer_final.zkey
COPY circuits/verification_key.json ./circuits/verification_key.json
COPY circuits/transfer.r1cs ./circuits/transfer.r1cs

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

EXPOSE 8080

CMD ["/app/entrypoint.sh"]
