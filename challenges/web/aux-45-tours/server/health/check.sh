#!/bin/sh
set -eu
curl -s --output - -F 'file=@/health/sample.mp3' http://localhost:8000/api/convert | grep 'encoder=Lavf'
