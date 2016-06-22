#include "clarcnet.h"

#include <cstdlib>

using namespace clarcnet;

int main(int argc, char* argv[]) {
	auto sv = server("1111");
	for (;;) {
		sv.process();
	}
	return EXIT_SUCCESS;
}