mov rax, 0
mov rdi, ![file_descriptor_location]!
mov rsi, ![buffer_location]!
mov rdx, ![size]!
syscall

mov ![buffer_location]!, rsi

