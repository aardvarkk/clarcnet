#pragma once

#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <errno.h>
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

	// #define thr \
	// 	throw std::runtime_error(\
	// 			std::string(__FILE__) + ":" +\
	// 			std::to_string(__LINE__) + " " +\
	// 			std::string(strerror(errno)));

	#define thr \
		throw std::runtime_error(\
				std::string(strerror(errno)));

	#define chk(val) \
	{\
		if (val < 0) {\
			thr;\
		}\
	}

	typedef uint16_t                           arr_len;
	typedef std::vector<uint8_t>               buffer;
	typedef std::chrono::high_resolution_clock clk;
	typedef uint8_t                            msg_id_t;
	typedef std::chrono::milliseconds          ms;
	typedef uint32_t                           packet_sz;
	typedef std::chrono::time_point<clk>       tp;

	enum msg_id : msg_id_t {
		ID_UNKNOWN,
		ID_CONNECTION,
		ID_DISCONNECTION,
		ID_TIMEOUT,
		ID_PING,
		ID_USER
	};

	static const char* _msg_strs[] = {
		"ID_UNKNOWN",
		"ID_CONNECTION",
		"ID_DISCONNECTION",
		"ID_TIMEOUT",
		"ID_PING",
		"ID_USER"
	};

	static const packet_sz _msg_type      = sizeof(packet_sz);
	static const packet_sz _msg_start     = _msg_type + sizeof(msg_id_t);
	static const packet_sz _max_arr_len   = std::numeric_limits<arr_len>::max();
	static const packet_sz _max_packet_sz = std::numeric_limits<packet_sz>::max();

	struct packet : buffer {
		packet() : packet(-1, ID_UNKNOWN) {}
		packet(int fd, msg_id mid) : buffer(_msg_start, 0), fd(fd), rpos(_msg_start) { this->operator[](_msg_type) = mid; }
		int fd;
		int rpos;

		int8_t r_int8_t() {
			int8_t v = this->operator[](rpos);
			rpos += sizeof v;
			return v;
		}

		void w_int8_t(int8_t const& v) {
			push_back(v);
		}

		std::vector<uint8_t> r_vuint8_t() {
			std::vector<uint8_t> vec;
			arr_len sz = r_int16_t();
			vec.resize(sz);
			for (auto& v : vec)
				v = r_int8_t();
			return vec;
		}

		void w_vuint8_t(std::vector<uint8_t> const& vec) {
			w_int16_t(static_cast<arr_len>(vec.size()));
			insert(end(), vec.begin(), vec.end());
		}

		int16_t r_int16_t() {
			int16_t v = ntohs(*reinterpret_cast<int16_t*>(&this->operator[](rpos)));
			rpos += sizeof v;
			return v;
		}

		void w_int16_t(int16_t const& v) {
			int16_t vn = htons(v);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof v);
		}

		int32_t r_int32_t() {
			int32_t v = ntohl(*reinterpret_cast<int32_t*>(&this->operator[](rpos)));
			rpos += sizeof v;
			return v;
		}

		void w_int32_t(int32_t const& v) {
			int32_t vn = htonl(v);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof v);
		}

		float r_float(int binplcs = 4) {
			return static_cast<float>(r_int32_t()) / (1<<binplcs);
		}

		void w_float(float const& v, int binplcs = 4) {
			return w_int32_t(static_cast<int32_t>(v * (1<<binplcs)));
		}

		std::vector<uint32_t> r_vuint32_t() {
			std::vector<uint32_t> vec;
			arr_len sz = r_int16_t();
			vec.resize(sz);
			for (auto& v : vec)
				v = r_int32_t();
			return vec;
		}

		void w_vuint32_t(std::vector<uint32_t> const& vec) {
			w_int16_t(static_cast<arr_len>(vec.size()));
			for (auto const& v : vec)
				w_int32_t(v);
		}

		int64_t r_int64_t() {
			#ifdef __linux
			int64_t v = be64toh(*reinterpret_cast<int64_t*>(&this->operator[](rpos)));
			#else
			int64_t v = ntohll(*reinterpret_cast<int64_t*>(&this->operator[](rpos)));
			#endif
			rpos += sizeof v;
			return v;
		}

		void w_int64_t(int64_t const& v) {
			#ifdef __linux
			int64_t vn = htobe64(v);
			#else
			int64_t vn = htonll(v);
			#endif
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof v);
		}

		std::vector<uint64_t> r_vuint64_t() {
			std::vector<uint64_t> vec;
			arr_len sz = r_int16_t();
			vec.resize(sz);
			for (auto& v : vec)
				v = r_int64_t();
			return vec;
		}

		void w_vuint64_t(std::vector<uint64_t> const& vec) {
			w_int16_t(static_cast<arr_len>(vec.size()));
			for (auto const& v : vec)
				w_int64_t(v);
		}

		std::string r_string() {
			std::string str;
			arr_len sz = r_int16_t();
			uint8_t* p = &this->operator[](rpos);
			str = std::string(p, p + sz);
			rpos += sz;
			return str;
		}

		void w_string(std::string const& str) {
			w_int16_t(static_cast<arr_len>(str.length()));
			insert(end(), str.begin(), str.end());
		}
	};

	typedef std::vector<packet> packets;

	struct client_info {
	public:
		client_info() : buf(_msg_start, 0), len(0), tgt(0), last_ping(clk::now()) {}

		char      addr_str[INET6_ADDRSTRLEN];
		buffer    buf;
		tp        last_ping;
		packet_sz len;
		packet_sz tgt;
	};

	enum ret_code {
		SUCCESS,
		FAILURE,
		DISCONNECTED
	};

	class peer {
	public:

		ret_code send(int fd, packet& p) {
			if (p.empty() || p.size() > _max_packet_sz) return FAILURE;

			*(packet_sz*)&p[0] = htonl(p.size());
			ssize_t len = ::send(fd, &p[0], p.size(), 0);

			if (len > 0) return SUCCESS;
			else if (len == ECONNRESET) return DISCONNECTED;
			else thr;
		}

		ret_code close(int fd) {
			if (fd >= 0) {
				int err = ::close(fd);
				chk(err);
				fd = -1;
				return SUCCESS;
			} else {
				return DISCONNECTED;
			}
		}

		int fd;

	protected:

		static void* in_addr(sockaddr* sa) {
			switch (sa->sa_family) {
				case AF_INET  : return &((sockaddr_in*) sa)->sin_addr ;
				case AF_INET6 : return &((sockaddr_in6*)sa)->sin6_addr;
				default       : return nullptr;
			}
		}

		ret_code receive(int fd, client_info& ci, packets& ps) {

			buffer& b = ci.buf;

			if (b.size() - ci.len == 0)
				b.resize(b.size() * 2);

			ssize_t len = recv(fd, &b[ci.len], b.size() - ci.len, 0);
			if (len > 0) {
				int off = 0;
				while (len) {

					if (!ci.tgt && (ci.len + len >= sizeof(ci.tgt))) {
						ci.tgt = ntohl(*(packet_sz*)&b[off]);

						if (ci.tgt > _max_packet_sz) {
							return DISCONNECTED;
						}

						ci.len += sizeof ci.tgt;
						len    -= sizeof ci.tgt;
					}

					if (!ci.tgt || (ci.len + len < ci.tgt)) {
						ci.len += len;
						return SUCCESS;
					}

					packet p;
					p.fd = fd;
					p.clear();
					p.insert(p.end(), b.begin() + off, b.begin() + off + ci.tgt);
					ps.push_back(p);

					len -= ci.tgt - ci.len;
					assert(len >= 0);
					off += ci.tgt;

					ci.len = 0;
					ci.tgt = 0;
				}
			}
			else if (len == 0) {
				return DISCONNECTED;
			}
			else {
				if (errno == ECONNRESET) {
					return DISCONNECTED;
				}
				else if (errno == EAGAIN || errno == EWOULDBLOCK) {

				} else {
					thr;
				}
			}

			return SUCCESS;
		}
	};

	class server : public peer {
	public:
		server(uint16_t port, ms ping_period = ms(5000)) {
			this->ping_period = ping_period;

			int err;
			socklen_t val;

			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_INET6;
			hints.ai_flags    = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);

			inet_ntop(res->ai_family, in_addr(res->ai_addr), addr_str, sizeof addr_str);

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);

			val = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof val);
			chk(err);

			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
			chk(err);

			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof val);
			chk(err);

			err = bind(fd, res->ai_addr, res->ai_addrlen);
			chk(err);

			err = listen(fd, 0);
			chk(err);

			freeaddrinfo(res);
		}

		packets process() {
			packets ret;

			sockaddr_storage client;
			socklen_t sz = sizeof client;
			int client_fd = accept(fd, (sockaddr*)&client, &sz);
			if (client_fd < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {

				} else {
					thr;
				}
			} else {
				conns.insert(std::make_pair(client_fd, client_info()));
				inet_ntop(client.ss_family, in_addr((sockaddr*)&client), conns[client_fd].addr_str, sizeof conns[client_fd].addr_str);

				int err = fcntl(client_fd, F_SETFL, O_NONBLOCK);
				chk(err);

				ret.push_back(packet(client_fd, ID_CONNECTION));
			}

			tp now = clk::now();

			for (auto fd_to_ci = conns.begin(); fd_to_ci != conns.end();) {
				int cfd = fd_to_ci->first;
				client_info& ci = fd_to_ci->second;

				if (now - ci.last_ping >= ping_period) {
					packet ping = packet(cfd, ID_PING);
					if (send(cfd, ping) != SUCCESS) {
						close(cfd);
						fd_to_ci = conns.erase(fd_to_ci);
						continue;
					}
					ci.last_ping = now;
				}

				auto code = receive(cfd, ci, ret);
				switch (code) {
					case DISCONNECTED:
					{
						ret.push_back(packet(cfd, ID_DISCONNECTION));
						close(cfd);
						fd_to_ci = conns.erase(fd_to_ci);
						continue;
					}
					break;

					default:
					break;
				}
				++fd_to_ci;
			}

			return ret;
		}

		std::string address(int cfd) { auto fd_to_ci = conns.find(cfd); return fd_to_ci == conns.end() ? "" : fd_to_ci->second.addr_str; }

		char addr_str[INET6_ADDRSTRLEN];

	protected:
		std::unordered_map<int, client_info> conns;
		ms ping_period;
	};

	class client : public peer {
	public:
		client(std::string const& host, uint16_t port, ms timeout = ms(0)) {
			addrinfo hints    = {};
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			int err;
			if ((err = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);

			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);

			socklen_t val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof val);
			chk(err);

			err = connect(fd, res->ai_addr, res->ai_addrlen);
			if (err < 0 && errno != EINPROGRESS) {
				thr;
			}

			this->conn_start = clk::now();
			this->connected  = false;
			this->timeout    = timeout;
		}

		packets process() {

			packets ret;

			if (fd < 0) {
				ret.push_back(packet(fd, ID_DISCONNECTION));
				return ret;
			}

			if (!connected) {

				if (timeout != ms(0)) {
					auto waited = std::chrono::duration_cast<ms>(
						clk::now() - this->conn_start);
					if (waited >= timeout) {
						ret.push_back(packet(fd, ID_TIMEOUT));
						return ret;
					}
				}

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
				chk(err);
				if (val < 0) {
					if (errno == EINPROGRESS) {
						return ret;
					} else {
						thr;
					}
				}

				this->connected = true;

				freeaddrinfo(res);

				ret.push_back(packet(fd, ID_CONNECTION));

				return ret;
			}

			auto code = receive(fd, ci, ret);
			switch (code) {
				case DISCONNECTED:
				{
					ret.push_back(packet(fd, ID_DISCONNECTION));
					close(fd);
					connected = false;
				}
				break;

				default:
				break;
			}

			return ret;
		}

	protected:
		tp            conn_start;
		bool      		connected;
		addrinfo* 		res;
		client_info   ci;
		ms            timeout;
	};
}
