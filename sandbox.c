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


#ifndef PR_SYS_DISPATCH_INCLUSIVE_ON
#define PR_SYS_DISPATCH_INCLUSIVE_ON 1
#endif

#ifndef PR_SYS_DISPATCH_EXCLUSIVE_ON
#define PR_SYS_DISPATCH_EXCLUSIVE_ON 2
#endif

//assembly definition of trampoline
__asm__(
    ".global syscall_trampoline\n"
    "syscall_trampoline:\n"
    "    syscall\n"
    "    ret\n"
);

int policy_arr[512] = {0};
static volatile char selector = SYSCALL_DISPATCH_FILTER_BLOCK; // start in "intercept" mode


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
    if(syscall_nr<0 || syscall_nr>512){
        return 0;
    }
    if (!policy_arr[syscall_nr]){
        return 0;
    }
    return 1; // or 0
}

// 3. The Signal Handler
void sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    greg_t *regs = uc->uc_mcontext.gregs;
    int syscall_nr = (int)regs[REG_RAX];

    if (!is_syscall_allowed(syscall_nr)) {
        selector = SYSCALL_DISPATCH_FILTER_ALLOW;  // allow libc to write/exit safely
        write(STDERR_FILENO, "Sandbox violation detected!\n", 28);
        _exit(1);
    }

    greg_t return_addr = regs[REG_RIP] + 2;
    regs[REG_RSP] -= 8;
    *(uintptr_t *)regs[REG_RSP] = return_addr;
    regs[REG_RIP] = (greg_t)&syscall_trampoline;
}



// 4. The Setup
__attribute__((constructor))
void init_sandbox() {
    // A. Load Policy File ...
    FILE *policy_file = fopen("policy.txt", "r");
    if (!policy_file) {
        perror("policy");
        _exit(1);
    }

    int sc;
    while (fscanf(policy_file, "%d", &sc) == 1) {
        if (sc >= 0 && sc < 512)
            policy_arr[sc] = 1;
    }
    fclose(policy_file);


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
    size_t len = 16; // Approximate size of trampoline code
    
    // Using INCLUSIVE mode:
    // - Syscalls FROM the trampoline region are allowed (bypass filter)
    // - Syscalls from everywhere else trigger SIGSYS (get intercepted)
    
     if (prctl(PR_SET_SYSCALL_USER_DISPATCH, 
              PR_SYS_DISPATCH_ON,  // Use INCLUSIVE mode
              (unsigned long)start, 
              (unsigned long)64, 
              (void *)&selector) < 0) {
        perror("prctl failed");
        exit(1);
    }
}