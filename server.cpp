#include "clarcnet.h"

#include <cstdlib>
#include <execinfo.h>
#include <iostream>
#include <mutex>
#include <signal.h>
#include <thread>
#include <unistd.h>

using namespace clarcnet;
using namespace std;

void network(server* sv) {
	for (;;) {
		packets ps = sv->process();

		// std::cout << "got " << ps.size() << " packets" << std::endl;

		for (auto const& p : ps) {
			switch (p.mid) {
				case ID_CONNECTION:
				{
					std::cout << "client " << p.fd << " connected from " << sv->address(p.fd) << std::endl;

					packet r(0, ID_USER);
					r.push_back('w');
					r.push_back('e');
					r.push_back('l');
					r.push_back('c');
					r.push_back('o');
					r.push_back('m');
					r.push_back('e');
					auto sent = sv->send(p.fd, r);
					assert(sent == r.size());
				}
				break;

				case ID_DISCONNECTION:
				{
					std::cout << "client " << p.fd << " disconnected" << std::endl;
				}
				break;

				case ID_USER:
				{
					std::cout << "client " << p.fd << " sent user data of size " << p.size() << std::endl;
					for (auto i = 1; i < p.size(); ++i)
						std::cout << p[i];
					std::cout << std::endl;
				}
				break;

				default:
					break;
			}
		}
	}
}

int main(int argc, char* argv[]) {

	server* sv = new server(1111);
	cout << "created server at " << sv->addr_str << endl;

	thread t(network, sv);

	t.join();

	delete sv;
}