# write(1, message, 12) 
        mov     $1, %rax                # system call 1 is write 
        mov     $1, %rdi                # file handle 1 is stdout 
        mov     $message, %rsi 
        mov     $12, %rdx               # number of bytes 
        syscall                         # invoke operating system to do the write 
        # exit(0) 
        mov     $60, %rax 
        xor     %rdi, %rdi              # we want return code 0 
        syscall                         # invoke operating system to exit 
message: 
        .ascii  "Hello world\n"
