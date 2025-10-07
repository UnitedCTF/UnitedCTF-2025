FROM python:3.12-slim-bullseye

USER root

RUN mkdir /asm
COPY ./source/asm/level3 /asm/

RUN apt-get update && \
    apt-get install -y socat nasm gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN chown -R root:root /asm && \
    chmod -R 700 /asm

COPY ./level3/flag /flag


EXPOSE 1439

WORKDIR /app/runner

COPY ./source/core ./core
COPY ./source/__init__.py ./source/main.py ./
COPY ./source/commands/level3 ./commands

WORKDIR /app

COPY ./level3/run.sh ./run.sh
ENV COMMAND_ASM_FOLDER=/asm
ENV DEBUG=1

ENTRYPOINT ["sh","/app/run.sh"]