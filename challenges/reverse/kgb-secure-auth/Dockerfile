FROM debian:latest

WORKDIR /app

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

COPY ./src/server ./src/flag.txt ./entrypoint.sh ./

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 1337

ENTRYPOINT [ "/app/entrypoint.sh" ]
