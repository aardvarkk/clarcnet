#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", 1111);

	for (;;) {

		auto ps = cl.process();

		for (auto const& p : ps) {

			switch (p[_msg_type]) {
				case ID_CONNECTION_ACCEPTED:
				{
					packet p(0, ID_STRING);
					p.push_back('1');
					p.push_back('2');
					p.push_back('3');
					p.push_back('4');
					p.push_back('5');
					p.push_back('6');
					p.push_back('7');
					cl.send(cl.fd, p);

					packet p2(0, ID_STRING);
					p2.push_back('h');
					p2.push_back('e');
					p2.push_back('l');
					p2.push_back('l');
					p2.push_back('o');
					cl.send(cl.fd, p2);

					packet p3(0, ID_STRING);
					for (auto i = 0; i < 100000; ++i)
						p3.push_back('a' + i % 26);
					cl.send(cl.fd, p3);
				}
				break;

				case ID_DISCONNECTION:
				{
					return EXIT_FAILURE;
				}
				break;
			}
		}
	}
	return EXIT_SUCCESS;
}