FROM python:3.12-slim-bullseye

USER root

RUN mkdir /asm
COPY source/asm/level1 /asm/

RUN apt-get update && \
    apt-get install -y socat nasm gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN chown -R root:root /asm && \
    chmod -R 700 /asm


EXPOSE 1437

WORKDIR /app/runner

COPY source/core ./core
COPY source/__init__.py source/main.py ./
COPY source/commands/level1 ./commands

WORKDIR /app

COPY ./level1/run.sh ./run.sh
ENV COMMAND_ASM_FOLDER=/asm
ENV DEBUG=1
ENTRYPOINT ["sh","/app/run.sh"]