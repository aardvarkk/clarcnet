#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", 1111);

	for (;;) {

		auto ps = cl.process();

		for (auto const& p : ps) {

			switch (p[_msg_type]) {
				case CONNECTION:
				{
					packet p(0, STRING);
					p.push_back('1');
					p.push_back('2');
					p.push_back('3');
					p.push_back('4');
					p.push_back('5');
					p.push_back('6');
					p.push_back('7');
					cl.send(p);

					packet p2(0, STRING);
					p2.push_back('h');
					p2.push_back('e');
					p2.push_back('l');
					p2.push_back('l');
					p2.push_back('o');
					cl.send(p2);
				}
				break;

				case DISCONNECTION:
				{
					cl.close();
					return EXIT_FAILURE;
				}
				break;
			}
		}
	}
	return EXIT_SUCCESS;
}