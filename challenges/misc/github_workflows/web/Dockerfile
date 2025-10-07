# Build stage
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM ubuntu:latest
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates gh git && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/github_workflows /app/app
COPY static /app/static
COPY chall.bundle /app/chall.bundle
COPY Rocket.toml /app/Rocket.toml
COPY generate_new_challenge.sh /app/script.sh
EXPOSE 8000
ENV ORG_NAME=D8-Workflows-v2
ENV REPO_NAME=chall
ENV BUNDLE_PATH=/app/chall.bundle
ENV GH_TOKEN=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
LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025
ENV SCRIPT_PATH=/app/script.sh
ENTRYPOINT ["/app/app"]
