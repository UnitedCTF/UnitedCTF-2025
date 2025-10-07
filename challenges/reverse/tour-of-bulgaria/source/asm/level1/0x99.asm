; flag-61b156c1-4941-4e4b-8092-a78d11be7dc6
mov rdx, 0x0000000000000A36
push rdx
mov rdx, 0x6364376562313164
push rdx
mov rdx, 0x3837612d32393038
push rdx
mov rdx, 0x2d623465342d3134
push rdx
mov rdx, 0x39342d3163363531
push rdx
mov rdx, 0x6231362d67616c66
push rdx

mov rax, 1              
mov rdi, 1              
mov rsi, rsp           
mov rdx, 42              
syscall

mov rax, 60            
xor rdi, rdi            
syscall