#!/bin/sh
{
node - <<'__EOF__'
for(let i = 1; i <= 100000; i++) {
    if(Math.random() < 0.5) console.log(`CBG:${i}`);
}
__EOF__
} | gzip > breached-rooms.lst.gz