#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <set>
#include <unordered_map>
#include <vector>

namespace clarcnet {

	static const int _buffer_sz = 1<<13;

	void* in_addr(sockaddr* sa) {
		switch (sa->sa_family) {
			case AF_INET  : return &((sockaddr_in*) sa)->sin_addr ;
			case AF_INET6 : return &((sockaddr_in6*)sa)->sin6_addr;
			default       : return nullptr;
		}
	}

	typedef std::vector<uint8_t> buffer;

	struct client_data {
	public:
		client_data() : buf(_buffer_sz, 0), off(0), len(0) {}

		buffer buf;
		int    off;
		int    len;
	};

	class server {
	public:
		server(std::string const& port) {
			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_INET6;
			hints.ai_flags    = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(nullptr, port.c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (fd == -1) {
				throw std::runtime_error(strerror(errno));
			}

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			int off = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			err = bind(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			err = listen(fd, 0);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			inet_ntop(res->ai_family, in_addr(res->ai_addr), addr_str, sizeof addr_str);
			std::cout << addr_str << std::endl;

			freeaddrinfo(res);
		}

		void process() {
			sockaddr_storage client;
			socklen_t sz = sizeof client;
			err = accept(fd, (sockaddr*)&client, &sz);
			if (err < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {

				} else {
					throw std::runtime_error(strerror(errno));
				}
			} else {
				int client_fd = err;
				inet_ntop(client.ss_family, in_addr((sockaddr*)&client), addr_str, sizeof addr_str);
				std::cout << addr_str << std::endl;
				clients[client_fd];
			}

			for (auto& c_to_cd : clients) {
				int client_fd = c_to_cd.first;
				client_data& cd = c_to_cd.second;

				buffer& b = cd.buf;
				err = recv(client_fd, &b[cd.off], b.size() - cd.len, 0);
				if (err > 0) {
					cd.len += err;
					// for (auto i = 0; i < cd.len; ++i)
					// 	std::cout << std::hex << +b[i];
					// std::cout << std::endl;
				}
				else if (err < 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {

					} else {
						throw std::runtime_error(strerror(errno));
					}
				}
			}
		}

	protected:
		int  err;
		int  fd;
		char addr_str[INET6_ADDRSTRLEN];

		std::unordered_map<int, client_data> clients;
	};

	class client {
	public:
		client(std::string const& host, std::string const& port) {
			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (fd == -1) {
				throw std::runtime_error(strerror(errno));
			}

			err = connect(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			if (err < 0) {
				throw std::runtime_error(strerror(errno));
			}

			freeaddrinfo(res);
		}

		void process() {
			static bool sent = false;
			if (!sent) {
				err = send(fd, "123", 3, 0);
				if (err < 0) {
					throw std::runtime_error(strerror(errno));
				} else {
					std::cout << err << std::endl;
				}
				sent = !sent;
			}
		}

	protected:
		int err;
		int fd;
	};
}
