#include "clarcnet.h"

#include <cstdlib>
#include <execinfo.h>
#include <iostream>
#include <signal.h>
#include <unistd.h>

using namespace clarcnet;

int main(int argc, char* argv[]) {

	auto sv = server(1111);
	std::cout << "created server at " << sv.addr_str << std::endl;

	for (;;) {
		auto ps = sv.process();

		if (ps.empty()) continue;

		std::cout << "got " << ps.size() << " packets" << std::endl;

		for (auto const& p : ps) {
			switch (p[_msg_type]) {
				case ID_CONNECTION_ACCEPTED:
				{
					std::cout << "client " << p.fd << " connected from " << sv.address(p.fd) << std::endl;
				}
				break;

				case ID_DISCONNECTION:
				{
					std::cout << "client " << p.fd << " disconnected" << std::endl;
				}
				break;

				case ID_STRING:
				{
					std::cout << "client " << p.fd << " sent STRING of size " << p.size() << std::endl;
					// for (auto i = _msg_start; i < p.size(); ++i)
						// std::cout << p[i];
					// std::cout << std::endl;
				}
				break;
			}
		}

		// every now and again decide to send something
	}
	return EXIT_SUCCESS;
}