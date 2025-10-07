FROM python:3.12-slim-bullseye

WORKDIR /app

COPY level3/ ./

COPY ../source /app

RUN apt-get update && \
apt-get install -y socat && \
    apt-get clean && \
    pip install -r ./requirements.txt && \
    rm -rf /var/lib/apt/lists/*


RUN chmod +x run.sh
ENV FLAG=flag-bb36f046-2f2b-4ab0-aec0-ac45ca5fbf1b
EXPOSE 1439

ENTRYPOINT ["sh","/app/run.sh"]