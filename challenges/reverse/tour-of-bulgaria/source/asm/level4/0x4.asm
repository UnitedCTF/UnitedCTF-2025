mov rax, 1               
mov rdi, ![file_descriptor_location]!            
mov rsi, ![buffer_location]!
mov rdx, ![size]!
syscall