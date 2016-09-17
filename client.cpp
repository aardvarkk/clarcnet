#include "clarcnet.h"

#include <cstdlib>
#include <iostream>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	client* cl = new client("localhost", 1111, clarcnet::ms(10000));

	for (;;) {

		auto ps = cl->process();

		for (auto const& p : ps) {

			switch (p.mid) {
				case ID_CONNECTION:
				{
					std::cout << "connected" << std::endl;

					packet p(0, ID_USER);
					p.push_back('1');
					p.push_back('2');
					p.push_back('3');
					p.push_back('4');
					p.push_back('5');
					p.push_back('6');
					p.push_back('7');
					cl->send(p);

					packet p2(0, ID_USER);
					p2.push_back('h');
					p2.push_back('e');
					p2.push_back('l');
					p2.push_back('l');
					p2.push_back('o');
					auto sent = cl->send(p2);
					assert(sent == p2.size());

					// packet p3(0, ID_USER);
					// for (auto i = 0; i < 100000; ++i)
					// 	p3.push_back('a' + i % 26);
					// cl->send(p3);
				}
				break;

				case ID_DISCONNECTION:
				{
					std::cout << "disconnected" << std::endl;
					return EXIT_FAILURE;
				}
				break;

				case ID_TIMEOUT:
				{
					std::cout << "timed out" << std::endl;
					return EXIT_FAILURE;
				}
				break;

				case ID_USER:
				{
					std::cout << "server " << p.fd << " sent user data of size " << p.size() << std::endl;
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
	return EXIT_SUCCESS;
}