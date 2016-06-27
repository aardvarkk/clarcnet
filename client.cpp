#include "clarcnet.h"

#include <cstdlib>
#include <iostream>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", 1111, std::chrono::milliseconds(5000));

	for (;;) {

		auto ps = cl.process();

		for (auto const& p : ps) {

			switch (p[_msg_type]) {
				case ID_CONNECTION:
				{
					packet p(0, ID_USER);
					p.push_back('1');
					p.push_back('2');
					p.push_back('3');
					p.push_back('4');
					p.push_back('5');
					p.push_back('6');
					p.push_back('7');
					cl.send(cl.fd, p);

					packet p2(0, ID_USER);
					p2.push_back('h');
					p2.push_back('e');
					p2.push_back('l');
					p2.push_back('l');
					p2.push_back('o');
					cl.send(cl.fd, p2);

					packet p3(0, ID_USER);
					for (auto i = 0; i < 100000; ++i)
						p3.push_back('a' + i % 26);
					cl.send(cl.fd, p3);
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

				case ID_PING:
				{
					std::cout << "ping" << std::endl;
				}
			}
		}
	}
	return EXIT_SUCCESS;
}