FROM python:3.13.5-slim

WORKDIR /app

RUN echo "=== [1/5] Installing system deps ===" \
 && apt-get update && apt-get install -y curl bash ca-certificates jq bzip2 \
 && rm -rf /var/lib/apt/lists/*

RUN echo "=== [2/5] Installing Solana CLI ===" \
 && curl -L https://github.com/solana-labs/solana/releases/download/v1.18.14/solana-release-x86_64-unknown-linux-gnu.tar.bz2 \
    -o solana.tar.bz2 \
 && tar xjf solana.tar.bz2 \
 && mv solana-release/bin/solana /usr/local/bin/solana \
 && rm -rf solana-release solana.tar.bz2 \
 && echo "✅ Solana CLI installed"

RUN echo "=== [3/5] Installing Sugar ===" \
 && curl -sSf https://sugar.metaplex.com/install.sh | bash \
 && mv /root/bin/sugar /usr/local/bin/sugar \
 && echo "✅ Sugar installed"

COPY requirements.txt .
RUN echo "=== [4/5] Installing Python deps ===" \
 && pip install --no-cache-dir -r requirements.txt

COPY . .
COPY mon_owner.json /root/mon_owner.json
RUN echo "=== [5/5] Setting Solana config ===" \
 && solana config set --keypair /root/mon_owner.json --url https://api.devnet.solana.com || echo "⚠ Solana config failed"

ENV OWNER_WALLET=/root/mon_owner.json
ENV RPC_URL=https://api.devnet.solana.com
ENV CANDY_MACHINE_ID=8HnVy3UeSJsqz4ZbuChiSgGrcTbeogJtrM9Fx3SFba8E
ENV COLLECTION_MINT=6Qo9R5KGboAANBLo5paZSbHK5rH2Yr2bFLLDw5dm9Tjr

EXPOSE 5000

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]

