FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main .
RUN mkdir /app/tmp

FROM scratch

ENV FLAG=flag-R0undTripS3ri41iz4ti0nIsW4k_ee696fb1
ENV INITIAL_BOOK_PATH="/initial_book.md"


COPY --from=builder /app/main /main
COPY --from=builder /app/initial_book.md /
COPY --from=builder /app/tmp /tmp

EXPOSE 8080

ENTRYPOINT ["/main"]
