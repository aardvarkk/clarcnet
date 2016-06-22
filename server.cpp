#include "clarcnet.h"

#include <cstdlib>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto sv = server("1111");
	for (;;) {

		auto cps = sv.process();
		for (auto const& cp : cps) {
			std::cout << "got packet of size " << cp.p.size() << " from client " << cp.fd << std::endl;
			for (auto i = 0; i < cp.p.size(); ++i)
				std::cout << std::hex << cp.p[i];
			std::cout << std::endl;
		}

		// every now and again decide to send something
	}
	return EXIT_SUCCESS;
}