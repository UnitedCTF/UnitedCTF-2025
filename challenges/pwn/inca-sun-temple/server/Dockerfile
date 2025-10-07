FROM debian:bookworm

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 1000

RUN apt-get -y update && apt-get install -y --no-install-recommends socat

WORKDIR /srv

RUN echo "flag-caf4c732954438d6" > /flag.txt

COPY challenge /
RUN chmod +x /challenge

ENTRYPOINT ["socat", "TCP-LISTEN:1000,reuseaddr,fork", "SYSTEM:'/challenge',stderr"]
