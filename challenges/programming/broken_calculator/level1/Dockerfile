FROM python:3.12-slim-bullseye

WORKDIR /app

COPY level1/ ./

COPY ../source /app

RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    pip install -r ./requirements.txt && \
    rm -rf /var/lib/apt/lists/*


RUN chmod +x run.sh

ENV FLAG=flag-7e1c825e-26c5-42d4-9dfb-3eee80ebc870
EXPOSE 1437

ENTRYPOINT ["sh","/app/run.sh"]