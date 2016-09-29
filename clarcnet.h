#pragma once

#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <queue>
#include <random>
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
	 			std::string(strerror(errno)) + " (" +\
				std::to_string(errno) + ")");

#define chk(val) \
	{\
		if (val < 0) {\
			thr;\
		}\
	}

	enum msg_id : uint8_t {
		ID_UNKNOWN,
		ID_VERSION,
		ID_CONNECTION,
		ID_DISCONNECTION,
		ID_HEARTBEAT,
		ID_TIMEOUT,
		ID_USER
	};

	static const char* msg_strs[ID_USER+1] = {
		"ID_UNKNOWN",
		"ID_VERSION",
		"ID_CONNECTION",
		"ID_DISCONNECTION",
		"ID_HEARTBEAT",
		"ID_TIMEOUT",
		"ID_USER"
	};

	typedef std::chrono::high_resolution_clock clk;
	typedef std::chrono::milliseconds          ms;
	typedef std::chrono::time_point<clk>       tp;

	enum ret_code
	{
		SUCCESS,
		FAILURE,
		DISCONNECTED,
		WAITING
	};

	struct streambuffer : std::vector<uint8_t> {
		int    rpos;  // current reading position

		streambuffer() : rpos(0) {}

		size_t r_size_t() {
			uint8_t intro = r_int8_t();

			if (intro <= 0xFA) {
				return intro;
			}
			else if (intro == 0xFB) {
				return static_cast<uint8_t>(r_int8_t());
			}
			else if (intro == 0xFC) {
				return static_cast<uint16_t>(r_int16_t());
			}
			else if (intro == 0xFD) {
				return static_cast<uint32_t>(r_int32_t());
			}
			else if (intro == 0xFE) {
				return static_cast<uint64_t>(r_int64_t());
			}

			throw std::runtime_error("Invalid size!");
		}

		void w_size_t(size_t const& sz) {
			if (sz <= 0xFA) {
				w_int8_t(sz);
			}
			else if (sz <= UINT8_MAX) {
				w_int8_t(0xFB);
				w_int8_t(sz);
			}
			else if (sz <= UINT16_MAX) {
				w_int8_t(0xFC);
				w_int16_t(sz);
			}
			else if (sz <= UINT32_MAX) {
				w_int8_t(0xFD);
				w_int32_t(static_cast<int32_t>(sz));
			}
			else if (sz <= UINT64_MAX) {
				w_int8_t(0xFE);
				w_int64_t(sz);
			} else {
				throw std::runtime_error("Invalid size!");
			}
		}

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
			vec.resize(r_size_t());

			for (auto& v : vec) v = r_int8_t();

			return vec;
		}

		void w_vuint8_t(std::vector<uint8_t> const& vec) {
			w_size_t(vec.size());
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

		float r_float(int binplcs = 16) {
			return static_cast<float>(r_int32_t()) / (1<<binplcs);
		}

		void w_float(float const& v, int binplcs = 16) {
			return w_int32_t(static_cast<int32_t>(v * (1<<binplcs)));
		}

		std::vector<uint32_t> r_vuint32_t() {
			std::vector<uint32_t> vec;
			vec.resize(r_size_t());

			for (auto& v : vec) v = r_int32_t();

			return vec;
		}

		void w_vuint32_t(std::vector<uint32_t> const& vec) {
			w_size_t(vec.size());

			for (auto const& v : vec) w_int32_t(v);
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
			vec.resize(r_size_t());

			for (auto& v : vec) v = r_int64_t();

			return vec;
		}

		void w_vuint64_t(std::vector<uint64_t> const& vec) {
			w_size_t(vec.size());

			for (auto const& v : vec) w_int64_t(v);
		}

		std::string r_string() {
			std::string str;
			auto sz = r_size_t();
			uint8_t* p = &this->operator[](rpos);
			str = std::string(p, p + sz);
			rpos += sz;
			return str;
		}

		void w_string(std::string const& str) {
			w_size_t(str.length());
			insert(end(), str.begin(), str.end());
		}
	};

	struct packet : streambuffer {

		int          fd;
		uint8_t      mid;

		packet() : packet(-1, ID_UNKNOWN) {}
		packet(msg_id mid) : packet(-1, mid) {}
		packet(int fd, msg_id mid) : fd(fd), mid(mid) {}
	};

	typedef std::vector<packet> packets;

	struct delayed_send {
		delayed_send() : delayed_send(-1, packet(), clk::now()) {}
		delayed_send(int fd, packet&& p, tp const& earliest) : fd(fd), p(p), earliest(earliest) {}

		int    fd;
		packet p;
		tp     earliest;
	};

	// Returns ADDITIONAL bytes required in the header given the intro byte
	static size_t header_bytes_req(uint8_t intro) {
		// payload <= 250 bytes
		if (intro <= 0xFA) {
			return 0;
		}
		// payload <= UINT8_MAX
		else if (intro == 0xFB) {
			return 1;
		}
		// payload <= UINT16_MAX
		else if (intro == 0xFC) {
			return 2;
		}
		// payload <= UINT32_MAX
		else if (intro == 0xFD) {
			return 4;
		}
		// payload <= UINT64_MAX
		else if (intro == 0xFE) {
			return 8;
		}
		else {
			throw std::runtime_error("Invalid intro byte!");
		}
	}

	struct receive_state {

		receive_state() : state(MessageID), recvd(0), req(1) {
			w.resize(1 + header_bytes_req(0xFE)); // request maximum header size
		}

		enum state {
			MessageID,
			HeaderIntro,
			Header,
			Payload
		};

		state  state; // current state
		size_t recvd; // bytes received while in this state
		size_t req;   // bytes required to exit this state
		packet w;     // working packet to receive into
	};

	class peer {

	public:

		peer() : fd(-1), lag_min(ms(0)), lag_max(ms(0)) {
			std::random_device rdev;
			rng.seed(rdev());
		}

		ret_code close(int fd) {
			int err = ::close(fd);
			chk(err);
			return SUCCESS;
		}

		int fd;
		ms lag_min, lag_max;

	protected:

		// Don't pass along heartbeats -- they're internal
		void remove_heartbeats(packets& ps)
		{
			// Don't pass along heartbeats -- they're internal
			ps.erase(std::remove_if(
			             ps.begin(),
			             ps.end(),
			[](packet const& p) {
				return p.mid == ID_HEARTBEAT;
			}
			         ), ps.end());
		}

		// Non-blocking check if writing is possible
		bool poll_write() {
			pollfd ufds = { 0 };
			ufds.fd = fd;
			ufds.events = POLLOUT;
			int err = poll(&ufds, 1, 0);
			chk(err);

			if (!(ufds.revents & POLLOUT)) {
				return false;
			}

			int val;
			socklen_t val_sz = sizeof val;
			err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &val, &val_sz);
			chk(err);

			if (val < 0) {
				if (errno == EINPROGRESS) {
					return false;
				} else {
					thr;
				}
			}

			return true;
		}

		ret_code send_sock(int fd, void const* data, size_t sz) {
			if (sz == 0) return SUCCESS;

			size_t sent = 0;

			while (sent < sz) {
				auto len = ::send(fd, data, sz - sent, 0);

				if (len > 0) sent += len;

				if (sent == sz) {
					return SUCCESS;
				}
				else if (len == 0) {
					return DISCONNECTED;
				}
				else if (len < 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						poll_write();
					}
					else if (errno == ECONNRESET || errno == EPIPE) {
						return DISCONNECTED;
					}
					else {
						thr;
					}
				}
			}

			return FAILURE;
		}

		ret_code send_packet(int fd, packet &p) {
			// Message ID
			auto code = send_sock(fd, &p.mid, sizeof(p.mid));
			if (code != SUCCESS) return code;

			// If it's a heartbeat, we're done!
			if (p.mid == ID_HEARTBEAT) return code;

			// Header
			streambuffer header;
			header.w_size_t(p.size());
			code = send_sock(fd, &header.front(), header.size());
			if (code != SUCCESS) return code;

			// Payload
			code = send_sock(fd, &p.front(), p.size());
			return code;
		}

	protected:

		static void* in_addr(sockaddr* sa) {
			switch (sa->sa_family) {
			case AF_INET  :
				return &((sockaddr_in*) sa)->sin_addr ;

			case AF_INET6 :
				return &((sockaddr_in6*)sa)->sin6_addr;

			default       :
				return nullptr;
			}
		}

		void flush_backlog() {
			auto now = clk::now();

			while (!delayed.empty()) {
				if (delayed.front().earliest > now) break;

				delayed_send ds = delayed.front();
				ret_code code = send_packet(ds.fd, ds.p);

				if (code != SUCCESS) {
					break;
				}

				delayed.pop_front();
			}
		}

		ret_code send(int fd, packet&& p) {
			if (!lag_max.count()) {
				return send_packet(fd, p);
			} else {
				std::uniform_int_distribution<> dist_lag(
				    static_cast<int>(lag_min.count()),
				    static_cast<int>(lag_max.count())
				);
				ms lag(dist_lag(rng));
				delayed.emplace_back(delayed_send(fd, std::move(p), clk::now() + lag));
				return SUCCESS;
			}
		}

		ret_code recv_into(int fd, void* buffer, size_t bytes, size_t& recvd) {
			if (!bytes) return SUCCESS;

			// Try to retrieve exactly the number required
			ssize_t len = recv(fd, buffer, bytes, 0);

			// Mark the new size since we've received bytes
			if (len > 0) recvd += len;

			if (len == bytes) {
				return SUCCESS;
			}
			else if (len == 0) {
				return DISCONNECTED;
			}
			else if (len > 0) {
				return WAITING;
			}
			else {
				if (errno == ECONNRESET || errno == ETIMEDOUT) {
					return DISCONNECTED;
				}
				else if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return WAITING;
				} else {
					thr;
				}
			}
		}

		void finish_packet(int fd, receive_state& r, packets &ps) {
			assert(fd > 0);
			assert(r.recvd == r.req);
			r.w.rpos = 0;
			r.w.resize(r.req);
			r.w.fd = fd;
			ps.emplace_back(std::move(r.w));
			r = receive_state();
		}

		ret_code receive(int fd, receive_state& r, packets &ps) {

			// Keep going while we are receiving packets!
			for (;;) {

				if (r.state == receive_state::MessageID) {
					auto code = recv_into(fd, &r.w.mid, r.req - r.recvd, r.recvd);
					if (code != SUCCESS) return code;

					// If the message is a heartbeat, we're done!
					if (r.w.mid == ID_HEARTBEAT) {
						finish_packet(fd, r, ps);
						continue;
					}

					r.state = receive_state::HeaderIntro;
					r.recvd = 0;
					r.req   = 1;
				}

				if (r.state == receive_state::HeaderIntro) {
					auto code = recv_into(fd, &r.w.front(), r.req - r.recvd, r.recvd);
					if (code != SUCCESS) return code;

					r.state = receive_state::Header;
					r.recvd = 1;
					r.req   = 1 + header_bytes_req(r.w.front());
				}

				if (r.state == receive_state::Header) {
					auto code = recv_into(fd, &r.w[r.recvd], r.req - r.recvd, r.recvd);
					if (code != SUCCESS) return code;

					r.state = receive_state::Payload;
					r.recvd = 0;
					r.req   = r.w.r_size_t();
				}

				if (r.state == receive_state::Payload) {

					for (;;) {

						// allocate more space as necessary
						// but don't resize directly to client request because they could make us allocate tons of memory!
						if (r.w.size() < r.req) r.w.resize(r.w.size() * 2);

						auto code = recv_into(fd, &r.w[r.recvd], std::min(r.w.size() - r.recvd, r.req - r.recvd), r.recvd);
						if (code != SUCCESS) return code;

						if (r.recvd == r.req) {
							finish_packet(fd, r, ps);
							break;
						}
					}
				}
			}
		}

		std::deque<delayed_send> delayed; // packets that we intentionally want to send late
		std::default_random_engine rng; // used to generate lag values
	};

	class server : public peer {

	public:
		server(uint16_t port, ms heartbeat_period = ms(4000), ms timeout = ms(15000)) {
			this->heartbeat_period = heartbeat_period;
			this->timeout = timeout;
			int err;
			addrinfo hints    = {}, *res;
			hints.ai_family   = AF_INET6;
			hints.ai_flags    = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if ((err = getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &res)) != 0) {
				throw std::runtime_error(gai_strerror(err));
			}

			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			chk(fd);
			err = fcntl(fd, F_SETFL, O_NONBLOCK);
			chk(err);
			socklen_t val;
			val = 0;
			err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof val);
			chk(err);
			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
			chk(err);
			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof val);
			chk(err);
#ifdef SO_NOSIGPIPE
			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof val);
			chk(err);
#endif
			err = bind(fd, res->ai_addr, res->ai_addrlen);
			chk(err);
			err = listen(fd, 0);
			chk(err);
			freeaddrinfo(res);
		}

		ret_code send(int fd, packet&& p) {
			auto it = conns.find(fd);
			if (it == conns.end()) return FAILURE;

			auto code = peer::send(fd, std::move(p));
			if (code == SUCCESS) it->second.last_packet_sent = clk::now();
			return code;
		}

		// server
		packets process(bool accept_new = true) {
			flush_backlog();
			packets ret;
			sockaddr_storage client;
			socklen_t sz = sizeof client;

			if (accept_new) {
				for (;;) {
					int cfd = accept(fd, (sockaddr*)&client, &sz);

					if (cfd < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							break;
						} else {
							thr;
						}
					} else {
						assert(!conns.count(cfd));
						conns.insert(std::make_pair(cfd, client_info()));
						inet_ntop(client.ss_family, in_addr((sockaddr*)&client), conns[cfd].addr_str, sizeof conns[cfd].addr_str);
						int err = fcntl(cfd, F_SETFL, O_NONBLOCK);
						chk(err);
#ifdef SO_NOSIGPIPE
						socklen_t val = 1;
						err = setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof val);
						chk(err);
#endif
						ret.emplace_back(packet(cfd, ID_CONNECTION));
					}
				}
			}

			tp now = clk::now();

			for (auto fd_to_ci = conns.begin(); fd_to_ci != conns.end();) {
				int cfd = fd_to_ci->first;
				client_info& ci = fd_to_ci->second;

				auto sz_pre = ret.size();
				auto code   = receive(cfd, ci.r, ret);
				auto sz_pst = ret.size();

				if (code == DISCONNECTED) {
					ret.emplace_back(packet(cfd, ID_DISCONNECTION));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
				} else {
					if (sz_pst != sz_pre) ci.last_packet_recv = now;

					if (now - ci.last_packet_recv > timeout) {
						ret.emplace_back(packet(cfd, ID_TIMEOUT));
						fd_to_ci = disconnect(fd_to_ci);
						continue;
					}

					if (now - max(ci.last_packet_sent, ci.last_packet_recv) >= heartbeat_period) {
						if (send(cfd, packet(cfd, ID_HEARTBEAT)) != SUCCESS) {
							ret.emplace_back(packet(cfd, ID_DISCONNECTION));
							fd_to_ci = disconnect(fd_to_ci);
							continue;
						}
					}
				}

				++fd_to_ci;
			}

			remove_heartbeats(ret);
			return ret;
		}

		std::string address(int cfd) {
			auto fd_to_ci = conns.find(cfd);
			return fd_to_ci == conns.end() ? "" : fd_to_ci->second.addr_str;
		}

		// External disconnect -- called by others
		// Since they pass a file descriptor, we know we can close it and reuse it since they should be done with it
		void disconnect(int cfd) {
			auto conn_it = conns.find(cfd);
			if (conn_it != conns.end()) disconnect(conn_it);
			peer::close(cfd);
		}

	protected:

		struct client_info {
			client_info() : last_packet_recv(clk::now()), recvd(0)
			{
				std::fill(addr_str, addr_str + sizeof addr_str, 0);
			}

			char          addr_str[INET6_ADDRSTRLEN];
			receive_state r;
			tp            last_packet_recv; // force timeout of client if they haven't responded
			tp            last_packet_sent; // know when to send more heartbeats
			size_t        recvd;            // number of bytes we've received from this client (pertaining to current packet)
		};

		typedef std::unordered_map<int, client_info> conn_map;

		// Internal disconnect -- called when we determine a client has disconnected or inactive
		conn_map::iterator disconnect(conn_map::iterator conn_it) {
			int cfd = conn_it->first;
			delayed.erase(remove_if(delayed.begin(), delayed.end(),
			[=](delayed_send const& ds) {
				return ds.fd == cfd;
			}), delayed.end());
			return conns.erase(conn_it);
		}

		conn_map conns;
		ms       heartbeat_period;
		ms       timeout;
	};

	class client : public peer {
	public:
		client(std::string const& host, uint16_t port, ms timeout = ms(0)) : last_packet_recv(clk::now()) {
			this->conn_start  = clk::now();
			this->connected   = false;
			this->timeout     = timeout;

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
			socklen_t val;
			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof val);
			chk(err);
#ifdef SO_NOSIGPIPE
			val = 1;
			err = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof val);
			chk(err);
#endif
			err = connect(fd, res->ai_addr, res->ai_addrlen);

			if (err < 0 && errno != EINPROGRESS) {
				thr;
			}
		}

		void disconnect() {
			peer::close(fd);
			fd = -1;
			connected = false;
		}

		ret_code send(packet&& p) {
			return peer::send(this->fd, std::move(p));
		}

		packets process() {
			flush_backlog();
			packets ret;

			if (fd < 0) return ret;

			if (!connected) {
				if (timeout != ms(0)) {
					auto waited = std::chrono::duration_cast<ms>(clk::now() - conn_start);

					if (waited >= timeout) {
						ret.emplace_back(packet(fd, ID_TIMEOUT));
						return ret;
					}
				}

				if (!poll_write()) return ret;

				connected = true;
				freeaddrinfo(res);
				ret.emplace_back(packet(fd, ID_CONNECTION));
				return ret;
			}

			auto code = receive(fd, r, ret);

			if (code == DISCONNECTED) {
				ret.emplace_back(packet(fd, ID_DISCONNECTION));
				return ret;
			}
		
			if (!ret.empty()) last_packet_recv = clk::now();

			for (auto const& p : ret) {
				if (p.mid != ID_HEARTBEAT) continue;
				if (send(packet(p)) != SUCCESS) {
					ret.emplace_back(packet(fd, ID_DISCONNECTION));
					return ret;
				}
			}

			if (timeout != ms(0) && clk::now() - last_packet_recv > timeout) {
				ret.emplace_back(packet(fd, ID_TIMEOUT));
				return ret;
			}
			
			remove_heartbeats(ret);
			return ret;
		}

	protected:
		tp            conn_start;
		bool          connected;
		tp            last_packet_recv;
		receive_state r;
		addrinfo*     res;
		ms            timeout;
	};
}
