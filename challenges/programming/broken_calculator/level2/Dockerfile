FROM python:3.12-slim-bullseye

WORKDIR /app

COPY level2/ ./

COPY ../source /app

RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    pip install -r ./requirements.txt && \
    rm -rf /var/lib/apt/lists/*


RUN chmod +x run.sh
ENV FLAG=flag-4b96f90a-ea5f-4138-afe5-c489438ac319
EXPOSE 1438

ENTRYPOINT ["sh","/app/run.sh"]