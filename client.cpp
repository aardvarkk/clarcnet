#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", "1111");

	for (;;) {

		auto ps = cl.process();

		for (auto const& p : ps) {
			switch (p.front()) {
				case CONNECTION:
				{
					spacket p;
					p.push_back(DEBUG);
					p.push_back('1');
					p.push_back('2');
					p.push_back('3');
					p.push_back('4');
					p.push_back('5');
					p.push_back('6');
					p.push_back('7');
					cl.send(p);

					spacket p2;
					p2.push_back(DEBUG);
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