FROM debian:bookworm AS builder

RUN apt update && apt install -y --no-install-recommends gcc libc6-dev

WORKDIR /build
COPY main.c .
RUN gcc main.c -fPIE -fstack-protector-all -ffreestanding -o challenge


FROM debian:bookworm

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 1000

RUN apt-get -y update && apt-get install -y --no-install-recommends socat

WORKDIR /srv

RUN echo "flag-d474d752b3103b66" > /flag.txt

COPY --from=builder /build/challenge /
RUN chmod +x /challenge

ENTRYPOINT ["socat", "TCP-LISTEN:1000,reuseaddr,fork", "SYSTEM:'/challenge',stderr"]
