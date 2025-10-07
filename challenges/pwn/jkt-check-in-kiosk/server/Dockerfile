FROM ubuntu:20.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -U -s /bin/bash ctf

WORKDIR /server
COPY challenge /server/challenge
RUN chown root:root /server/challenge && chmod 0755 /server/challenge

RUN echo "flag-wu92phofpc78upd9" > /tmp/flag.txt && chmod 0444 /tmp/flag.txt

USER ctf
EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/server/challenge,stderr"]
