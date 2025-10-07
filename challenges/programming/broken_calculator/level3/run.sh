#!/bin/sh
while true ; do socat -dd -T1800 tcp-l:1439,reuseaddr,fork,keepalive,su=nobody exec:"python3 level.py",stderr; done