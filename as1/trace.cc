#include <iostream>
#include <cstdint>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>

using namespace std::chrono_literals;

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
			std::cout << "child\n";
			std::this_thread::sleep_for(1000ms);

			auto ret = ptrace(PTRACE_TRACEME);
			std::cout << "traceme returned: " << ret << '\n';

			ret = execv(argc[1], {});
			std::cout << "execve returned: " << ret << '\n';

			break;
		}
		default: {
			std::cout << "parent, child pid: " << pid << '\n';
			std::this_thread::sleep_for(200ms);

			// auto ret = ptrace(PTRACE_SEIZE, pid);
			// std::println("ret: {}", ret);

			int status = 0;

			while(waitpid(pid, &status, __WALL) != -1);
			// std::println("status: {}", status);
			
			ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
			
			siginfo_t siginfo;
			ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(siginfo), &siginfo);
			std::cout << "siginfo: " << siginfo.si_code << '\n';

			break;
		}
	}

	return 0;
}
