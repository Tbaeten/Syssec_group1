#include <algorithm>
#include <csignal>
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
	if(argc < 3) {
		std::cerr << "usage: ./trace [policy_file_path] [bin]\n";
		return 1;
	}

	auto pid = fork();

	switch(pid) {
		case -1:
			std::cerr << "failed to fork\n";
			return 1;
		case 0: {
			log_child("up");
			
			char** args = new char*[argc-2];
			for(int i=2; i<argc; ++i)
				args[i-2] = argv[i];

			auto ret = ptrace(PTRACE_TRACEME);
			log_child("traceme returned: " + std::to_string(ret));
			
			log_child("starting execv");
			ret = execv(argv[2], args);
			log_child("execv returned: " + std::to_string(ret));

			log_child("down");
			break;
		}
		default: {
			std::ofstream out(argv[1]);
			std::vector<long> res;

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
				res.push_back(call);
				// ptrace(PTRACE_GET_SYSCALL_INFO, pid, 0, &call);
				// log_parent(std::to_string(call.instruction_pointer));
				// log_parent(std::to_string(call.entry.nr));
				// log_parent(std::to_string(call.seccomp.nr));
				std::cout << "called: " << call << '\n';
				// ptrace(PTRACE_CONT, pid);
			}

			std::sort(res.begin(), res.end());
			res.erase(std::unique(res.begin(), res.end()), res.end());

			for (auto c : res)
    			out << c << "\n";
			
			log_parent("down");
			break;
		}
	}

	return 0;
}
