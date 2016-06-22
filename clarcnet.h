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

			if ((err = getaddrinfo(nullptr, port.c_str(), &hints, &res)) != 0) {
				throw runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (fd == -1) {
				throw runtime_error(strerror(errno));
			}

			int off = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
			if (err < 0) {
				throw runtime_error(strerror(errno));
			}

			err = bind(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0) {
				throw runtime_error(strerror(errno));
			}

			err = listen(fd, 0);
			if (err < 0) {
				throw runtime_error(strerror(errno));
			}

			sockaddr_storage client;
			socklen_t sz = sizeof client;
			err = accept(fd, (sockaddr*)&client, &sz);
			if (err < 0) {
				throw runtime_error(strerror(errno));
			}

			freeaddrinfo(res);
		}

	protected:
		int fd;
	};

	class client {
	public:
		client(string const& host, string const& port) {

			int err;

			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res)) != 0) {
				throw runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (fd == -1) {
				throw runtime_error(strerror(errno));
			}

			err = connect(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0) {
				throw runtime_error(strerror(errno));
			}

			freeaddrinfo(res);
		}

	protected:
		int fd;
	};
}
