#include <csignal>
#include <iostream>
#include <cstdint>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>

// copied from `man ptrace`
struct ptrace_syscall_info {
  __u8 op;        /* Type of system call stop */
  __u32 arch;     /* AUDIT_ARCH_* value; see seccomp(2) */
  __u64 instruction_pointer; /* CPU instruction pointer */
  __u64 stack_pointer;    /* CPU stack pointer */
  union {
	  struct {    /* op == PTRACE_SYSCALL_INFO_ENTRY */
		  __u64 nr;       /* System call number */
		  __u64 args[6];  /* System call arguments */
	  } entry;
	  struct {    /* op == PTRACE_SYSCALL_INFO_EXIT */
		  __s64 rval;     /* System call return value */
		  __u8 is_error;  /* System call error flag;
							 Boolean: does rval contain
							 an error value (-ERRCODE) or
							 a nonerror return value? */
	  } exit;
	  struct {    /* op == PTRACE_SYSCALL_INFO_SECCOMP */
		  __u64 nr;       /* System call number */
		  __u64 args[6];  /* System call arguments */
		  __u32 ret_data; /* SECCOMP_RET_DATA portion
							 of SECCOMP_RET_TRACE
							 return value */
	  } seccomp;
  };
};

inline void log_child(const std::string &msg) {
#ifdef DEBUG
	std::cout << "[child]" << "    " << msg << '\n';
#endif
}

inline void log_parent(const std::string &msg) {
#ifdef DEBUG
	std::cout << "[parent]" << "   " << msg << '\n';
#endif
}

int32_t main(int argv, char** argc) {
	if(argv < 2) {
		std::cerr << "usage: ./trace [bin]\n";
		return 1;
	}

	auto pid = fork();

	switch(pid) {
		case -1:
			std::cerr << "failed to fork\n";
			return 1;
		case 0: {
			log_child("up");

			auto ret = ptrace(PTRACE_TRACEME);
			// log_child("traceme returned: " + std::to_string(ret));
			
			// kill(getpid(), SIGSTOP);
			
			// log_child("starting execve");
			ret = execv(argc[1], {});
			// log_child("execve returned: " + std::to_string(ret));

			log_child("down");
			break;
		}
		default: {
			log_parent("child pid: " + std::to_string(pid));

			int status;
			waitpid(pid, &status, 0);
			log_parent("wait status: " + std::to_string(status));
			
			int e = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
			
			while(true) {
				while(true) {
					int e = ptrace(PTRACE_SYSCALL, pid, 0, 0);
					
					log_parent("waiting....");
					int status;
					waitpid(pid, &status, 0);

					if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
						log_parent("stopped: " + std::to_string(status));
						break;
					}

					if (WIFEXITED(status))
						return 1;
				}

				// ptrace_syscall_info call;
				long call = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX);
				// ptrace(PTRACE_GET_SYSCALL_INFO, pid, 0, &call);
				// log_parent(std::to_string(call.instruction_pointer));
				// log_parent(std::to_string(call.entry.nr));
				// log_parent(std::to_string(call.seccomp.nr));
				std::cout << "called: " << call << '\n';
				// ptrace(PTRACE_CONT, pid);
			}
			
			log_parent("down");
			break;
		}
	}

	return 0;
}
