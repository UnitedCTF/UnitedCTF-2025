mov ![register]!, ![key]!
mov rcx, 0x0101010101010101
imul ![register]!, rcx
mov rdx, 0x0000000000005f6c
xor rdx, ![register]!
push rdx
mov rdx, 0x3663633465643066
xor rdx, ![register]!
push rdx
mov rdx, 0x6730337867656637
xor rdx, ![register]!
push rdx
mov rdx, 0x7837376461786631
xor rdx, ![register]!
push rdx
mov rdx, 0x6d6d7866656c6466
xor rdx, ![register]!
push rdx
mov rdx, 0x626c6c7832343933
xor rdx, ![register]!
push rdx


mov rax, 1              
mov rdi, 1              
mov rsi, rsp           
mov rdx, 42              
syscall

mov rax, 60            
xor rdi, rdi            
syscall