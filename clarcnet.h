#include <arpa/inet.h>
#include <cstring>
#include <deque>
#include <errno.h>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <set>
#include <unordered_map>
#include <vector>

namespace clarcnet {

	#define chk(val) { if (val < 0) throw std::runtime_error(strerror(errno)); }

	static const int _buffer_sz = 1<<13;

	typedef uint16_t             packet_sz;
	typedef uint8_t              msg_id;
	typedef std::vector<uint8_t> buffer;

	struct spacket : buffer {
		spacket() : buffer(sizeof(packet_sz), 0) {}
	};

	struct rpacket : buffer {
		int fd;
	};

	typedef std::vector<rpacket> rpackets;

	void* in_addr(sockaddr* sa) {
		switch (sa->sa_family) {
			case AF_INET  : return &((sockaddr_in*) sa)->sin_addr ;
			case AF_INET6 : return &((sockaddr_in6*)sa)->sin6_addr;
			default       : return nullptr;
		}
	}

	struct client_data {
	public:
		buffer    buf;
		packet_sz len;
		packet_sz tgt;

		client_data() : buf(_buffer_sz, 0), len(0), tgt(0) {}
	};

	enum msg_ids : msg_id {
		CONNECTED,
		DEBUG
	};

	class server {
	public:
		server(std::string const& port) {
			int val;

			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_INET6;
			hints.ai_flags    = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(nullptr, port.c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);

			val = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof val);
			chk(err);

			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
			chk(err);

			err = bind(fd, res->ai_addr, res->ai_addrlen);
			chk(err);

			err = listen(fd, 0);
			chk(err);

			inet_ntop(res->ai_family, in_addr(res->ai_addr), addr_str, sizeof addr_str);
			std::cout << addr_str << std::endl;

			freeaddrinfo(res);
		}

		rpackets process() {

			rpackets ret;

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

				rpacket p;
				p.fd = client_fd;
				p.push_back(CONNECTED);
				ret.push_back(p);
			}

			for (auto c_to_cd = clients.begin(); c_to_cd != clients.end();) {
				int client_fd = c_to_cd->first;
				client_data& cd = c_to_cd->second;

				buffer& b = cd.buf;
				err = recv(client_fd, &b[cd.len], b.size() - cd.len, 0);
				if (err > 0) {
					std::cout << "recv " << err << " bytes" << std::endl;

					// set target size
					if (!cd.tgt) {
						packet_sz tgt = *(packet_sz*)&b[0];
						cd.tgt = ntohs(tgt);
						std::cout << "packet length is " << cd.tgt << std::endl;
					}
					cd.len += err;

					// finished at least one packet
					if (cd.len >= cd.tgt) {
						// TODO: store full packet to pass back, remove it, and keep any "tail"
						ret.resize(ret.size()+1);
						rpacket& p = ret[ret.size()-1];

						p.fd = client_fd;
						p.insert(p.end(), b.begin() + sizeof(packet_sz), b.begin() + cd.tgt);
					}
				}
				else if (err == 0) {
					std::cout << "CLIENT " << client_fd << " DISCONNECTED!" << std::endl;

					// TODO: client disconn stuff
					c_to_cd = clients.erase(c_to_cd);
					continue;
				}
				else {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {

					} else {
						throw std::runtime_error(strerror(errno));
					}
				}

				++c_to_cd;
			}

			return ret;
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
			connected = false;

			addrinfo hints    = {};
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);

			err = connect(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0 && errno != EINPROGRESS) {
				throw std::runtime_error(strerror(errno));
			}
		}

		rpackets process() {

			rpackets ret;

			if (!connected) {
				fd_set check;
				FD_SET(fd, &check);
				timeval timeout = {};
				err = select(1, nullptr, &check, nullptr, &timeout);
				if (err < 0) {
					throw std::runtime_error(strerror(errno));
				}
				else {
					int val;
					socklen_t val_sz;
					err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &val, &val_sz);
					chk(err);
					chk(val);

					connected = true;
					freeaddrinfo(res);

					rpacket p;
					p.clear();
					p.push_back(CONNECTED);
					ret.push_back(p);
				}
			}

			return ret;
		}

		void send(spacket& p) {
			std::cout << "sending" << std::endl;

			*(packet_sz*)&p[0] = htons(p.size());
			err = ::send(fd, &p[0], p.size(), 0);
			chk(err)

			std::cout << "sent " << err << " bytes" << std::endl;
		}

	protected:
		bool      connected;
		int       err;
		int       fd;
		addrinfo* res;
	};
}
