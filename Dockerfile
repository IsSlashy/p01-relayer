# P-01 ZK Relayer Service
# Generates Groth16 proofs for mobile/extension clients

FROM node:20-slim

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

# Build TypeScript
RUN pnpm build

# Environment variables
ENV PORT=3000
ENV WASM_PATH=/app/circuits/transfer.wasm
ENV ZKEY_PATH=/app/circuits/transfer_final.zkey
ENV VERIFICATION_KEY_PATH=/app/circuits/verification_key.json
ENV SOLANA_RPC_URL=https://api.devnet.solana.com

EXPOSE 3000

CMD ["node", "dist/index.js"]
