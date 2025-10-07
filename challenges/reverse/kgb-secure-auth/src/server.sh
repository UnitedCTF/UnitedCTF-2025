#!/bin/sh
socat -dd -T1800 tcp-l:1337,reuseaddr,fork,keepalive exec:"./server",stderr
