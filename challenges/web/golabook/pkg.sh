#!/bin/bash

OUTPUT="chall.tar.gz"
FILES=("main.go" "go.sum" "go.mod" "Dockerfile" "compose.yml" "initial_book.md" "cmd/api/api.go" "cmd/config/config.go" "cmd/config/config_enum.go" "cmd/database/database.go" "cmd/utils/index_enum.go" "client/main.go")

mkdir chall && cp -r . chall/ && rm -rf chall/chall
cd chall
sed -i -E -e 's/flag-\w+/flag-Redacted/g' Dockerfile
tar -czvf "../$OUTPUT" "${FILES[@]}"
cd .. && rm -rf chall

echo "Packaging complete: $OUTPUT"
