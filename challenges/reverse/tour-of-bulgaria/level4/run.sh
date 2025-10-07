#!/bin/sh


python /webserver/main.py &

while :; do
    socat -dd -T1800 tcp-l:1440,reuseaddr,fork,keepalive,su=root exec:"python3 /app/runner/main.py,pty",stderr
done