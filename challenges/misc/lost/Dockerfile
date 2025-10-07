FROM golang:1.24.5 AS go-build

WORKDIR /build
COPY ./src /build

RUN CGO_ENABLED=0 GOOS=linux \
      go build \
        -o "bin/challenge" \
        "./cmd/challenge"

FROM scratch

ENV \
  SSH_ADDR=tcp4://0.0.0.0:10456 \
  SSH_USER=paul \
  SSH_PASS=i_hope_you_wont_need_this \
  SSH_FLAG=flag-idk_where_you_are_but_heres_a_flag_for_your_trouble_4a1818496f8c0048

LABEL org.opencontainers.image.source=https://github.com/UnitedCTF/UnitedCTF2025

EXPOSE 10456

COPY --from=go-build /build/bin/challenge /bin/challenge

ENTRYPOINT ["/bin/challenge"]
