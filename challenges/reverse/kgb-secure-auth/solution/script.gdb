# Just after function call to get length (before for loop)
b *0x401a1a

# Before `test %bl, %bl`
b *0x401a96

# Before first call to `operator+=`
b *0x401ae1

run 127.0.0.1 1337 < /dev/null

set $length=$eax
set $ipx=0
continue

while ($ipx<$length)
    set $bl=0x0
    continue
    set $rsi=$rbp-0x50
    continue
    set $ipx=$ipx+1
end
