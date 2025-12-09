#include <print>
#include <cstdint>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>

using namespace std::chrono_literals;

int32_t main(int argv, char** argc) {
	if(argv < 2) {
		std::println(stderr, "usage: ./trace [bin]");
		return 1;
	}

	auto pid = fork();

	switch(pid) {
		case -1:
			std::println(stderr, "failed to fork");
			return 1;
		case 0: {
			std::println("child");
			std::this_thread::sleep_for(1000ms);

			ptrace(PTRACE_TRACEME);

			int ret = execv(argc[1], {});
			std::println("execve returned: {}", ret);

			break;
		}
		default: {
			std::println("parent, child pid: {}", pid);
			std::this_thread::sleep_for(200ms);

			// auto ret = ptrace(PTRACE_SEIZE, pid);
			// std::println("ret: {}", ret);

			int status = 0;

			// while(waitpid(pid, &status, __WALL) != -1);
			// std::println("status: {}", status);

			siginfo_t siginfo;
			ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
			std::println("siginfo: {}", siginfo.si_code);

			break;
		}
	}

	return 0;
}
