#include <algorithm>
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
#include <fstream>

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
					// ptrace(PTRACE_SYSEMU, pid, 0, 0);
					ptrace(PTRACE_SYSCALL, pid, 0, 0);
					
					log_parent("waiting....");
					int status;
					waitpid(pid, &status, 0);


				//long call = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX);
				//long rdx = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * REG_RDX);
				//	std::cout << "rax: " << call << '\n';
				//	std::cout << "rdx: " << rdx << '\n';
					
					//if(call == 1 ) // && rdx == 0x6)
					//	getchar();



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


				if(call == 10 && rdx == 0x6) {
					user_regs_struct s;
					int err = ptrace(PTRACE_GETREGS, pid, nullptr, &s);
					std::cout << "blocking...\n";
					// std::cout << err << '\n';
					// std::cout << s.orig_rax << '\n';
					s.orig_rax = 3;
					s.rdi = -1;
					// s.rsi = 0;
					// s.rdx = 1;
					ptrace(PTRACE_SETREGS, pid, nullptr, &s);
				}
				if((call == 257 && rdx == 0x2) || 
				   (call == 2 && rdx == 0x2)
				) {// && rdx == 0x6) { 
					//std::cout << "rax: " << call << '\n';
					// std::cout << "rdx: " << rdx << '\n';
					// ptrace(PTRACE_SYSCALL, pid, 0, 0);
					user_regs_struct s;
					int err = ptrace(PTRACE_GETREGS, pid, nullptr, &s);
					long ptr = s.rsi;
					std::cout << "rsi: " << ptr << '\n';
					int i=0;
					std::string path;
					char last = '$';
					while(true) {
						char x = ptrace(PTRACE_PEEKDATA, pid, ptr+i*sizeof(char), 0);
						if(!x)
							break;
						// std::cout << x << '\n';
						if(last != '/' || x != '/')
							path.push_back(x);
						last = x;
						++i;
					}
					
					std::cout << "path: " << path << '\n';
					if(path.size() && path.back() == '/')
						path.pop_back();
					if(path != "/proc/self/mem")
						continue;
					std::cout << "blocking...\n";
					// std::cout << err << '\n';
					// std::cout << s.orig_rax << '\n';
					s.orig_rax = 3;
					s.rdi = -1;
					// s.rsi = 0;
					// s.rdx = 1;
					ptrace(PTRACE_SETREGS, pid, nullptr, &s);
				}
				// ptrace(PTRACE_GET_SYSCALL_INFO, pid, 0, &call);
				// log_parent(std::to_string(call.instruction_pointer));
				// log_parent(std::to_string(call.entry.nr));
				// log_parent(std::to_string(call.seccomp.nr));
				//std::cout << "called: " << call << '\n';
				// ptrace(PTRACE_CONT, pid);
			}

			log_parent("down");
			break;
		}
	}

	return 0;
}
