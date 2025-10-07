mov rax, 9             
xor rdi, rdi         
mov rsi, ![size]!
mov rdx, 3         
mov r10, 0x22         
xor r8, r8            
xor r9, r9         

syscall                
mov ![result_register]!, rax