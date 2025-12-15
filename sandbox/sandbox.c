#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
# define PR_SET_SYSCALL_USER_DISPATCH 59
# define PR_SYS_DISPATCH_OFF 0
# define PR_SYS_DISPATCH_ON 1
# define SYSCALL_DISPATCH_FILTER_ALLOW 0
# define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif

int policy_arr[512] = {0};
volatile char selector = SYSCALL_DISPATCH_FILTER_ALLOW;
void *trampoline_page = NULL;
int handler_count = 0;

// Safe debug write function for debugging, mostly unused in final code
void debug_write(const char *msg) {
    write(STDERR_FILENO, msg, strlen(msg));
}

void debug_write_num(const char *prefix, long num) {
    char buf[256];
    int len = snprintf(buf, sizeof(buf), "%s%ld\n", prefix, num);
    write(STDERR_FILENO, buf, len);
}

void debug_write_hex(const char *prefix, void *ptr) {
    char buf[256];
    int len = snprintf(buf, sizeof(buf), "%s%p\n", prefix, ptr);
    write(STDERR_FILENO, buf, len);
}

int is_syscall_allowed(int syscall_nr) {
    if(syscall_nr < 0 || syscall_nr >= 512){
        return 0;
    }
    return policy_arr[syscall_nr];
}

void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    handler_count++;
    
    // Set selector to ALLOW immediately to prevent recursion, otherwise syscall 15 keeps getting called
    selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    
    
    if (!ctx) {
        debug_write("ERROR: Context is NULL!\n");
        _exit(1);
    }
    
    ucontext_t *uc = (ucontext_t *)ctx;
    greg_t *regs = uc->uc_mcontext.gregs;
    int syscall_nr = (int)regs[REG_RAX];
    
    debug_write_num("Syscall number: ", syscall_nr); // just debug to check which call is happening
    
    // Don't intercept rt_sigreturn, or it will just end in recursion
    if (syscall_nr == 15) {
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        return;
    }
    
    // Check if syscall is from trampoline region
    unsigned long rip = (unsigned long)regs[REG_RIP];
    unsigned long tramp_start = (unsigned long)trampoline_page;
    unsigned long tramp_end = tramp_start + 4096;
    
    if (rip >= tramp_start && rip < tramp_end) {
        debug_write("Syscall from trampoline region - allowing\n");
        selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        return;
    }
    
    // Check policy
    int allowed = is_syscall_allowed(syscall_nr);
    
    if (!allowed) {
        char buf[100];
        int len = snprintf(buf, sizeof(buf), "\nSandbox violation: syscall %d blocked\n", syscall_nr);
        write(STDERR_FILENO, buf, len);
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        _exit(1);
    }
    
    greg_t return_addr = regs[REG_RIP];
    
    // Modify stack to set up return
    regs[REG_RSP] -= 8;
    uint64_t *stack_ptr = (uint64_t *)regs[REG_RSP];
    *stack_ptr = return_addr;
    
    // Jump to trampoline
    regs[REG_RIP] = (greg_t)trampoline_page;
    
}

__attribute__((constructor))
void init_sandbox() {
    debug_write("\n=== Sandbox Initialization Started ===\n");
    
    // Create executable trampoline dynamically
    trampoline_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline_page == MAP_FAILED) {
        perror("mmap failed");
        _exit(1);
    }
    
    unsigned char *code = (unsigned char *)trampoline_page;
    int offset = 0;
    
    // syscall instruction
    code[offset++] = 0x0f;
    code[offset++] = 0x05;
    
    // movb $1, selector_address
    // We'll use: mov BYTE PTR [rip+offset], 1
    code[offset++] = 0xc6;  // mov byte ptr
    code[offset++] = 0x05;  // [rip + disp32]
    
    // Calculate offset from next instruction to &selector
    // Next instruction will be at: trampoline_page + offset + 5 (4 byte disp + 1 byte imm)
    long selector_offset = (long)&selector - (long)(trampoline_page + offset + 5);
    
    // Write 32-bit offset (little endian)
    *(int32_t *)(code + offset) = (int32_t)selector_offset;
    offset += 4;
    
    // Write immediate value (1 = BLOCK)
    code[offset++] = SYSCALL_DISPATCH_FILTER_BLOCK;
    
    // ret instruction
    code[offset++] = 0xc3;
    
    
    // Load policy
    FILE *policy_file = fopen("policy.txt", "r");
    if (!policy_file) {
        perror("Failed to open policy.txt");
        _exit(1);
    }
    
    int sc;
    int policy_count = 0;
    while (fscanf(policy_file, "%d", &sc) == 1) {
        if (sc >= 0 && sc < 512) {
            policy_arr[sc] = 1;
            policy_count++;
        }
    }
    fclose(policy_file);
    
    // Always allow exit syscalls for cleanup
    policy_arr[60] = 1;  // exit
    policy_arr[231] = 1; // exit_group
    
    
    // Setup signal handler with alternate stack
    // this is done so that the main program stack doesn't overflow from multiple calls
    // to the signal handler, not needed for a simple sandbox, but we were running into
    // a recursion problem earlier (currently solved)
    stack_t ss;
    ss.ss_sp = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ss.ss_sp == MAP_FAILED) {
        perror("mmap signal stack failed");
        _exit(1);
    }
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    
    if (sigaltstack(&ss, NULL) < 0) {
        perror("sigaltstack failed");
        _exit(1);
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSYS, &sa, NULL) < 0) {
        perror("sigaction failed");
        _exit(1);
    }
    
    // Enable syscall user dispatch
    unsigned long start = (unsigned long)trampoline_page;
    unsigned long len = 4096;
    
    // main code that sets the SUD active
    
    if (prctl(PR_SET_SYSCALL_USER_DISPATCH,
              PR_SYS_DISPATCH_ON,
              start,
              len,
              &selector) < 0) {
        perror("prctl failed");
        debug_write_num("errno: ", errno);
        _exit(1);
    }
    
    // Now switch to blocking mode
    debug_write("About to set selector to BLOCK...\n");
    selector = SYSCALL_DISPATCH_FILTER_BLOCK;
    
    // Test syscall
    pid_t pid = getpid();
}

__attribute__((destructor))
void cleanup_sandbox() {
    selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    if (trampoline_page) {
        munmap(trampoline_page, 4096);
    }
}