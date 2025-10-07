FROM rust:latest AS builder

WORKDIR /usr/src/c2rs
COPY ./challenge/ .
RUN cargo build

FROM ubuntu:24.04

COPY --from=builder /usr/src/c2rs/target/debug/c2rs /app
COPY flag.txt /flag.txt

EXPOSE 8080

CMD ["/app"]
