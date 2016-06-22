#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto cl = client("localhost", "1111");
	for (;;) {
		cl.process();
	}
	return EXIT_SUCCESS;
}