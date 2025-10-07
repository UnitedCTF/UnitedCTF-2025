#!/bin/sh

while :; do
    socat -dd -T1800 tcp-l:1439,reuseaddr,fork,keepalive,su=root exec:"python3 /app/runner/main.py,pty",stderr
done