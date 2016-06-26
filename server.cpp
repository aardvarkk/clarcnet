#include "clarcnet.h"

#include <cstdlib>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto sv = server(1111);
	for (;;) {
		auto ps = sv.process();

		if (ps.empty()) continue;

		std::cout << "got " << ps.size() << " packets" << std::endl;

		for (auto const& p : ps) {
			switch (p[_msg_type]) {
				case CONNECTION:
				{
					std::cout << "client " << p.fd << " connected" << std::endl;
				}
				break;

				case DISCONNECTION:
				{
					std::cout << "client " << p.fd << " disconnected" << std::endl;
				}
				break;

				case STRING:
				{
					std::cout << "client " << p.fd << " sent STRING of size " << p.size() << std::endl;
					for (auto i = _msg_start; i < p.size(); ++i)
						std::cout << p[i];
					std::cout << std::endl;
				}
				break;
			}
		}

		// every now and again decide to send something
	}
	return EXIT_SUCCESS;
}