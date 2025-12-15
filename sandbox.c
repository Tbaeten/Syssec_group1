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

#ifndef PR_SET_SYSCALL_USER_DISPATCH
# define PR_SET_SYSCALL_USER_DISPATCH 59
# define PR_SYS_DISPATCH_OFF 0
# define PR_SYS_DISPATCH_ON 1
# define SYSCALL_DISPATCH_FILTER_ALLOW 0
# define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif

//assembly definition of trampoline
__asm__(
    ".global syscall_trampoline\n"
    "syscall_trampoline:\n"
    "    syscall\n"
    "    ret\n"
);

// 1. The Trampoline
// This global variable allows us to identify the memory range of this function
extern void syscall_trampoline(void);

// Assembly implementation (concept):
// global syscall_trampoline
// syscall_trampoline:
//    syscall
//    jmp %r15  <-- Jump back to where the original code left off

// 2. The Policy Checker
int is_syscall_allowed(int syscall_nr) {
    // Check your array/list loaded from file
    return 1; // or 0
}

// 3. The Signal Handler
void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    greg_t *regs = uc->uc_mcontext.gregs;
    
    // Get the syscall number (RAX holds the syscall number on x86_64)
    int syscall_nr = (int)regs[REG_RAX];

    if (!is_syscall_allowed(syscall_nr)) {
        const char *msg = "Sandbox violation detected!\n";
        write(STDOUT_FILENO, msg, 28);
        exit(1);
    }

    // Calculates where to return which is 2 bytes from the syscall
    greg_t return_addr = regs[REG_RIP] + 2;
    
    // simulates push onto user stack which does decrement the stack pointer by 8 bytes
    regs[REG_RSP] -= 8;

    // writes the return address into the memory at new stack pointer position
    *(uintptr_t *)regs[REG_RSP] = return_addr;

    // Hijacks instruction pointer to execute trampoline 
    regs[REG_RIP] = (greg_t)&syscall_trampoline;

}

// 4. The Setup
__attribute__((constructor))
void init_sandbox() {
    // A. Load Policy File ...
    
    // B. Setup Signal Handler

    struct sigaction sa = {0};
    sa.sa_sigaction = sigsys_handler;
    // getter of context of registers (RIP)
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;

    if (sigaction(SIGSYS, &sa, NULL) < 0) {
        perror("sigaction failed");
        exit(1);
    }

    // C. Enable Syscall User Dispatch
    // We set the allowed region to ONLY be the trampoline function.
    // Everything else will trigger SIGSYS.
    long start = (long)&syscall_trampoline;
    long end = start + 16; // Approximate size of trampoline code
    
    // Note: Constants might need to be defined if headers are old
    // PR_SET_SYSCALL_USER_DISPATCH = 59
    // PR_SYS_DISPATCH_ON = 1
    
    struct syscall_user_dispatch_config config = {
        .mode = PR_SYS_DISPATCH_ON,
        .offset = start,
        .len = end - start,
        .selector = 0, // Not using selector variable mode
    };

    if (syscall(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, &config) < 0) {
        perror("prctl failed");
        exit(1);
    }
}