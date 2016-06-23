#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	bool connected = false;
	auto cl = client("localhost", "1111");

	for (;;) {
		auto ps = cl.process();
		for (auto const& p : ps) {
			switch (p.front()) {
				case CONNECTED:
				{
					connected = true;
				}
				break;
			}
		}

		if (connected) {
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
			connected = false; // only try once
		}
	}
	return EXIT_SUCCESS;
}