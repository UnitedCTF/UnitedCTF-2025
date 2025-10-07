mov rax, 2
lea rdi, [rel ![filename]!] 
mov rsi, ![mode]!
or rsi, 0x40
mov rdx, 0o600
syscall

mov ![result_register]!, rax