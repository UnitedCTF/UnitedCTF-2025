FROM python:3.12-slim-bullseye

USER root
COPY ./source/asm/level4 /asm
COPY ./source/web/webserver /webserver
COPY ./level4/flag /42dc8201-4f3b-47bf-80d0-84db141dbd20

RUN apt-get update && \
    apt-get install -y socat nasm gcc && \
    apt-get clean && \
    pip install -r /webserver/requirements.txt && \
    rm -rf /var/lib/apt/lists/*

RUN chmod -t /tmp && \
    chmod -t /var/tmp

RUN chown -R root:root /asm && \
    chmod -R 700 /asm

RUN chown -R root:root /webserver && \
    chmod -R 700 /webserver

RUN chown -R root:root /42dc8201-4f3b-47bf-80d0-84db141dbd20 && \
    chmod -R 700 /42dc8201-4f3b-47bf-80d0-84db141dbd20

COPY ./source/web/server_data /server_data

RUN chmod 1777 /server_data


EXPOSE 1440
EXPOSE 5000

WORKDIR /app/runner

COPY ./source/core ./core
COPY ./source/__init__.py ./source/main.py ./
COPY ./source/commands/level4 ./commands

WORKDIR /app/

COPY ./level4/run.sh ./run.sh

ENV COMMAND_ASM_FOLDER=/asm
ENTRYPOINT ["sh","/app/run.sh"]