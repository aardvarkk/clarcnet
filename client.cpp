#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", "1111");
	for (;;) {
		// get messages from the server
		auto cps = cl.process();

		// every now and again decide to send something
	}
	return EXIT_SUCCESS;
}