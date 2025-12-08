#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

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
    
    // Get the syscall number (RAX holds the syscall number on x86_64)
    int syscall_nr = uc->uc_mcontext.gregs[REG_RAX];

    if (!is_syscall_allowed(syscall_nr)) {
        const char *msg = "Sandbox violation detected!\n";
        write(STDOUT_FILENO, msg, 28);
        exit(1);
    }

    // Prepare to redirect to trampoline
    
    // A. Save the original return address (RIP + 2 bytes for 'syscall' instr)
    // We put it in R15 so the trampoline knows where to return.
    uc->uc_mcontext.gregs[REG_R15] = uc->uc_mcontext.gregs[REG_RIP] + 2;

    // B. Hijack the Instruction Pointer (RIP) to point to our trampoline
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)&syscall_trampoline;
}

// 4. The Setup
__attribute__((constructor))
void init_sandbox() {
    // A. Load Policy File ...
    
    // B. Setup Signal Handler
    struct sigaction sa = {0};
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; // SA_NODEFER allows recursion if needed
    sigaction(SIGSYS, &sa, NULL);

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