#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace clarcnet {

	using namespace std;

	class server {
	public:
		server(string const& port) {

			int err;

			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_INET6;
			hints.ai_flags    = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(NULL, port.c_str(), &hints, &res)) != 0) {
				throw gai_strerror(err);
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (fd == -1) {
				throw strerror(errno);
			}

			int off = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
			if (err < 0) {
				throw strerror(errno);
			}

			// for (auto p = res; p; p = p->ai_next) {
			// 	void *addr;
			// 	string ipver;

			// 	if (p->ai_family == AF_INET) {
			// 		sockaddr_in *ipv4 = (sockaddr_in *)p->ai_addr;
			// 		addr = &(ipv4->sin_addr);
			// 		ipver = "IPv4";
			// 	} else {
			// 		sockaddr_in6 *ipv6 = (sockaddr_in6 *)p->ai_addr;
			// 		addr = &(ipv6->sin6_addr);
			// 		ipver = "IPv6";
			// 	}

			// 	char ipstr[INET6_ADDRSTRLEN];
			// 	if (!inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr)) {
			// 		throw errno;
			// 	}
			// 	printf("  %s: %s\n", ipver.c_str(), ipstr);
			// }

			freeaddrinfo(res);
		}

	private:
		int fd;
	};
}
