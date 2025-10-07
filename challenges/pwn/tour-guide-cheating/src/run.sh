while :; do
    socat -dd -T300 tcp-l:1337,reuseaddr,fork,keepalive,su=nobody exec:"./chall",stderr
done
