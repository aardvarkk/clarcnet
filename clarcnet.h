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
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <set>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace clarcnet {

	#define thr \
		throw std::runtime_error(\
				std::string(__FILE__) + ":" +\
				std::to_string(__LINE__) + " " +\
				std::string(strerror(errno)));

	#define chk(val) \
	{\
		if (val < 0) {\
			thr;\
		}\
	}

	static const int _buffer_sz = 1<<13;

	typedef uint16_t             packet_sz;
	typedef uint8_t              msg_id_t;
	typedef std::vector<uint8_t> buffer;

	struct spacket : buffer {
		spacket() : buffer(sizeof(packet_sz), 0) {}
	};

	enum msg_id : msg_id_t {
		CONNECTION,
		DISCONNECTION,
		PING,
		DEBUG
	};

	struct rpacket : buffer {
		rpacket() : fd(0) {}
		rpacket(int fd, msg_id mid) : fd(fd) { push_back(mid); }
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

	struct packet_buffer {
	public:
		buffer    buf;
		packet_sz len;
		packet_sz tgt;

		packet_buffer() : buf(_buffer_sz, 0), len(0), tgt(0) {}
	};

	enum ret_code {
		SUCCESS,
		DISCONNECTED
	};

	class peer {
	protected:
		ret_code receive(int fd, packet_buffer& cd, rpackets& ps) {

			buffer& b = cd.buf;
			int err = recv(fd, &b[cd.len], b.size() - cd.len, 0);
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
					rpacket p;
					p.fd = fd;
					p.insert(p.end(), b.begin() + sizeof(packet_sz), b.begin() + cd.tgt);
					ps.push_back(p);
				}
			}
			else if (err == 0) {
				return DISCONNECTED;
			}
			else {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {

				} else {
					thr;
				}
			}

			return SUCCESS;
		}

		ret_code close() {
			int err = ::close(fd);
			chk(err);
			fd = 0;
			return SUCCESS;
		}

		int fd;
	};

	class server : public peer {
	public:
		server(std::string const& port) {
			int err, val;

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
			int err = accept(fd, (sockaddr*)&client, &sz);
			if (err < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {

				} else {
					thr;
				}
			} else {
				int client_fd = err;
				inet_ntop(client.ss_family, in_addr((sockaddr*)&client), addr_str, sizeof addr_str);
				std::cout << addr_str << std::endl;
				conns[client_fd];
				ret.push_back(rpacket(client_fd, CONNECTION));
			}

			for (auto fd_to_pb = conns.begin(); fd_to_pb != conns.end();) {
				auto code = receive(fd_to_pb->first, fd_to_pb->second, ret);
				switch (code) {
					case DISCONNECTED:
					{
						ret.push_back(rpacket(fd_to_pb->first, DISCONNECTION));
						fd_to_pb = conns.erase(fd_to_pb);
						continue;
					}
					break;

					default:
					break;
				}
				++fd_to_pb;
			}

			return ret;
		}

	protected:
		char addr_str[INET6_ADDRSTRLEN];

		std::unordered_map<int, packet_buffer> conns;
	};

	class client : public peer {
	public:
		client(std::string const& host, std::string const& port) {
			connected = false;

			addrinfo hints    = {};
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			int err;
			if ((err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);

			err = connect(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0 && errno != EINPROGRESS) {
				thr;
			}
		}

		rpackets process() {

			rpackets ret;

			if (!fd) {
				ret.push_back(rpacket(fd, DISCONNECTION));
				return ret;
			}

			if (!connected) {
				pollfd ufds;
				ufds.fd = fd;
				ufds.events = POLLOUT;
				int err = poll(&ufds, 1, 0);
				chk(err);

				if (!(ufds.revents & POLLOUT)) {
					return ret;
				}

				int val;
				socklen_t val_sz = sizeof val;
				err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &val, &val_sz);
				std::cout << val_sz << std::endl;
				chk(err);
				if (val < 0) {
					if (errno == EINPROGRESS) {
						return ret;
					} else {
						thr;
					}
				}

				connected = true;
				freeaddrinfo(res);

				rpacket p;
				ret.push_back(rpacket(fd, CONNECTION));

				return ret;
			}

			auto code = receive(fd, pb, ret);
			switch (code) {
				case DISCONNECTED:
				{
					ret.push_back(rpacket(fd, DISCONNECTION));
					close();
				}
				break;

				default:
				break;
			}

			return ret;
		}

		void send(spacket& p) {
			std::cout << "sending" << std::endl;

			*(packet_sz*)&p[0] = htons(p.size());
			int err = ::send(fd, &p[0], p.size(), 0);
			chk(err);

			std::cout << "sent " << err << " bytes" << std::endl;
		}

	protected:
		bool      		connected;
		addrinfo* 		res;
		packet_buffer pb;
	};
}
