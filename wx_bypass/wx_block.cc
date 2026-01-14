#include <csignal>
#include <cstdio>
#include <iostream>
#include <cstdint>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <vector>
#include <sstream>

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

// block the syscall by changing it to 3 (close)
// in the argument we provide -1 (invalid file descriptor)
// so the syscall returns error code (-1), which happens
// to be error code for open and mprotect syscalls too
void block_syscall(size_t pid, user_regs_struct &s) {
	std::cout << "[wx_block] blocking...\n";
	s.orig_rax = 3;
	s.rdi = -1;
	ptrace(PTRACE_SETREGS, pid, nullptr, &s);
}

int32_t main(int argc, char** argv) {
	if(argc < 2) {
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
			
			char** args = new char*[argc-1];
			for(int i=1; i<argc; ++i)
				args[i-1] = argv[i];

			auto ret = ptrace(PTRACE_TRACEME);
			log_child("traceme returned: " + std::to_string(ret));
			
			log_child("starting execv");
			ret = execv(argv[1], args);
			log_child("execv returned: " + std::to_string(ret));

			log_child("down");
			break;
		}
		default: {
			log_parent("child pid: " + std::to_string(pid));

			int status;
			waitpid(pid, &status, 0);
			log_parent("wait status: " + std::to_string(status));
			
			int e = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
			log_parent("setoptions returned: " + std::to_string(e));
			
			bool ok = true;
			while(true) {
				while(true) {
					ptrace(PTRACE_SYSCALL, pid, 0, 0);
					
					log_parent("waiting....");
					int status;
					waitpid(pid, &status, 0);

					if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
						log_parent("stopped: " + std::to_string(status));
						break;
					}					
					if (WIFEXITED(status)) {
						ok = false;
						break;
					}
				}

				if(!ok)
					break;

				// ptrace_syscall_info call;
				long call = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX);
				long rdx = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * REG_RDX);
				long rsi = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * REG_RSI);

				// handle 'mprotect' with the options set to EXEC and WRITE at the same time
				if(call == 10 && ((rdx & 0x6) == 0x6)) {
					user_regs_struct s;
					int err = ptrace(PTRACE_GETREGS, pid, nullptr, &s);
					if(err < 0) {
						std::cerr << "failed to steal registers!\n";
						exit(1);
					}
					block_syscall(pid, s);
				}

				// handle 'open' and 'openat', with the O_RDWR flag
				if((call == 257 && rdx == 0x2) || (call == 2 && rsi == 0x2)) {
					user_regs_struct s;
					int err = ptrace(PTRACE_GETREGS, pid, nullptr, &s);
					if(err < 0) {
						std::cerr << "failed to steal registers!\n";
						exit(1);
					}

					long ptr = s.rsi;
					// the register containing the filepath is different for open
					if(call == 2) 
						ptr = s.rdi;
					int i=0;
					std::string path;
					char last = '$';
					while(true) {
						char x = ptrace(PTRACE_PEEKDATA, pid, ptr+i*sizeof(char), 0);
						// read until null character
						if(!x)
							break;
						// edge case: /bin//////ls 
						if(last != '/' || x != '/')
							path.push_back(x);
						last = x;
						++i;
					}

					// edge case: /bin/ls/
					if(path.size() && path.back() == '/')
						path.pop_back();

					log_parent("path: " + path);
					// check if the requested path is 
					// if(path != "/proc/self/mem")
					// 	continue;

					std::stringstream ss(path);
					std::string w;
					std::vector<std::string> path_split;
					while(std::getline(ss, w, '/'))
						path_split.push_back(w);

					// notice that it should block all paths in the format of:
					// /proc/[pid]/mem
					if(path_split.size() < 4 || path_split[1] != "proc" || path_split[3] != "mem")
						continue;
					
					block_syscall(pid, s);
				}
			}

			log_parent("down");
			break;
		}
	}

	return 0;
}
