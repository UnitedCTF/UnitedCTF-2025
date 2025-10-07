FROM debian:latest AS build
RUN apt-get update && apt-get install -y build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/main.c .
RUN gcc -Wall -o chall main.c

FROM debian:latest
RUN apt-get update && apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/chall .
COPY src/flag.txt .
COPY src/run.sh .

EXPOSE 1337

ENTRYPOINT ["sh","/app/run.sh"]
