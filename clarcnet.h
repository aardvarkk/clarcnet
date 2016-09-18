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
		ID_CONNECTION,
		ID_DISCONNECTION,
		ID_TIMEOUT,
		ID_HEARTBEAT,
		ID_USER
	};

	static const char* msg_strs[ID_USER+1] = {
		"ID_UNKNOWN",
		"ID_CONNECTION",
		"ID_DISCONNECTION",
		"ID_TIMEOUT",
		"ID_HEARTBEAT",
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
		size_t recvd; // can't use size() to determine what we've received -- may get less than we ask for on recv()

		streambuffer() : rpos(0), recvd(0) {}

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
		streambuffer header;

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

	class peer {

	public:

		peer() : fd(-1), lag_min(ms(0)), lag_max(ms(0)) {
			std::random_device rdev;
			rng.seed(rdev());
		}

		ret_code close(int fd) {
			if (fd >= 0) {
				int err = ::close(fd);

				if (err < 0 && errno != EBADF) thr;

				return SUCCESS;
			} else {
				return DISCONNECTED;
			}
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
			assert(sz);
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
			// Heartbeats are special messages (only one byte)
			if (p.mid == ID_HEARTBEAT) {
				uint8_t msg = 0xFF;
				return send_sock(fd, &msg, 1);
			}

			// Only heartbeats can have empty payloads (and no message ID byte!)
			if (p.empty()) {
				return FAILURE;
			}

			// Header
			p.header.clear();
			p.header.w_size_t(p.size());
			auto code = send_sock(fd, &p.header.front(), p.header.size());

			if (code != SUCCESS) {
				return code;
			}

			// Message ID
			code = send_sock(fd, &p.mid, sizeof(p.mid));

			if (code != SUCCESS) {
				return code;
			}

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
			// Don't assume we got anything
			recvd = 0;
			// Try to retrieve exactly the number required
			ssize_t len = recv(fd, buffer, bytes, 0);

			// Mark the new size since we've received bytes
			if (len > 0) recvd = len;

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

		ret_code recv_into(int fd, streambuffer& b, size_t bytes) {
			// Expand as we receive more data
			if (b.size() < b.recvd + bytes) b.resize(b.recvd + bytes);

			// Try to retrieve exactly the number required
			size_t recvd;
			auto code = recv_into(fd, &*(b.begin() + b.recvd), bytes, recvd);

			// Mark the new size since we've received bytes
			if (recvd > 0) b.recvd += recvd;

			return code;
		}

		void finish_packet(int fd, packet &w, packets &ps) {
			assert(fd > 0);
			w.fd = fd;
			ps.emplace_back(std::move(w));
			w = packet();
		}

		// returns total header size (INCLUDING intro byte) required based on the intro byte itself
		size_t header_bytes_req(uint8_t intro) {
			// payload <= 250 bytes
			if (intro <= 0xFA) {
				return 1;
			}
			// payload <= UINT8_MAX
			else if (intro == 0xFB) {
				return 2;
			}
			// payload <= UINT16_MAX
			else if (intro == 0xFC) {
				return 3;
			}
			// payload <= UINT32_MAX
			else if (intro == 0xFD) {
				return 5;
			}
			// payload <= UINT64_MAX
			else if (intro == 0xFE) {
				return 9;
			}
			// heartbeat
			else if (intro == 0xFF) {
				return 1;
			}
			else {
				throw std::runtime_error("Invalid intro byte!");
			}
		}

		ret_code receive(int fd, packet &w, packets &ps) {
			// Keep going while we are receiving packets!
			for (;;) {
				// Step 1 -- get the intro byte
				if (!w.header.recvd) {
					auto code = recv_into(fd, w.header, 1);

					if (code != SUCCESS) return code;
				}

				// Step 2 -- if the intro is a heartbeat, we're done!
				if (w.header.front() == 0xFF) {
					w.mid = ID_HEARTBEAT;
					finish_packet(fd, w, ps);
					continue;
				}

				// Step 3 -- get the rest of the header
				auto header_sz_req = header_bytes_req(w.header.front());

				if (w.header.recvd < header_sz_req) {
					auto code = recv_into(fd, w.header, header_sz_req - w.header.recvd);

					if (code != SUCCESS) return code;
				}

				// Step 4 -- get the message ID
				// Sending ID_UNKNOWN is unsupported as we will not take it as valid input
				if (w.mid == ID_UNKNOWN) {
					size_t recvd;
					auto code = recv_into(fd, &w.mid, 1, recvd);

					if (code != SUCCESS) return code;
				}

				// Step 5 -- get the payload
				w.header.rpos = 0;
				auto payload_sz = w.header.r_size_t();

				if (w.recvd < payload_sz) {
					auto code = recv_into(fd, w, payload_sz - w.recvd);

					if (code != SUCCESS) return code;
				}

				finish_packet(fd, w, ps);
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
			if (!conns.count(fd)) return FAILURE;

			return peer::send(fd, std::move(p));
		}

		packets process(bool accept_new = true) {
			flush_backlog();
			packets ret;
			sockaddr_storage client;
			socklen_t sz = sizeof client;

			if (accept_new) {
				for (;;) {
					int client_fd = accept(fd, (sockaddr*)&client, &sz);

					if (client_fd < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							break;
						} else {
							thr;
						}
					} else {
						assert(!conns.count(client_fd));
						conns.insert(std::make_pair(client_fd, client_info()));
						inet_ntop(client.ss_family, in_addr((sockaddr*)&client), conns[client_fd].addr_str, sizeof conns[client_fd].addr_str);
						int err = fcntl(client_fd, F_SETFL, O_NONBLOCK);
						chk(err);
#ifdef SO_NOSIGPIPE
						socklen_t val = 1;
						err = setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof val);
						chk(err);
#endif
						ret.push_back(packet(client_fd, ID_CONNECTION));
					}
				}
			}

			tp now = clk::now();

			for (auto fd_to_ci = conns.begin(); fd_to_ci != conns.end();) {
				int cfd = fd_to_ci->first;
				client_info& ci = fd_to_ci->second;

				if (now - ci.last_packet_sent >= heartbeat_period) {
					if (send(cfd, packet(cfd, ID_HEARTBEAT)) != SUCCESS) {
						disconnect(cfd);
						continue;
					}

					ci.last_packet_sent = now;
				}

				auto code = receive(cfd, ci.w, ret);

				switch (code) {
				case DISCONNECTED:
				{
					fd_to_ci = disconnect(fd_to_ci);
					ret.emplace_back(packet(cfd, ID_DISCONNECTION));
				}

				continue;

				default:
					break;
				}

				if (!ret.empty())
					ci.last_packet_recv = now;

				if (now - ci.last_packet_recv > timeout) {
					ret.emplace_back(packet(cfd, ID_TIMEOUT));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
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

		void disconnect(int cfd) {
			auto it = conns.find(cfd);

			if (it == conns.end()) return;

			disconnect(it);
		}

	protected:

		struct client_info {
			client_info() :
				last_packet_sent(clk::now()),
				last_packet_recv(clk::now())
			{
				std::fill(addr_str, addr_str + sizeof addr_str, 0);
			}

			char   addr_str[INET6_ADDRSTRLEN];
			packet w; // working packet we're constructing
			tp     last_packet_sent;
			tp     last_packet_recv;
		};

		typedef std::unordered_map<int, client_info> conn_map;

		conn_map::iterator disconnect(conn_map::iterator conn_it) {
			int cfd = conn_it->first;
			delayed.erase(remove_if(delayed.begin(), delayed.end(),
			[=](delayed_send const& ds) {
				return ds.fd == cfd;
			}), delayed.end());
			close(conn_it->first);
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
			close(fd);
			fd = -1;
			connected = false;
		}

		ret_code send(packet&& p) {
			return peer::send(this->fd, std::move(p));
		}

		packets process() {
			flush_backlog();
			packets ret;

			if (fd < 0) {
				return ret;
			}

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

			auto code = receive(fd, w, ret);

			switch (code) {
			case DISCONNECTED:
			{
				ret.emplace_back(packet(fd, ID_DISCONNECTION));
				disconnect();
			}
			break;

			default:
				break;
			}

			if (!ret.empty())
				last_packet_recv = clk::now();

			for (auto const& p : ret) {
				if (p.mid != ID_HEARTBEAT) continue;

				// Respond with copied heartbeat packet
				if (send(packet(p)) != SUCCESS) {
					ret.emplace_back(packet(fd, ID_DISCONNECTION));
					disconnect();
					return ret;
				}
			}

			if (timeout != ms(0) && clk::now() - last_packet_recv > timeout) {
				ret.emplace_back(packet(fd, ID_TIMEOUT));
				disconnect();
			}

			remove_heartbeats(ret);
			return ret;
		}

	protected:
		tp        conn_start;
		bool      connected;
		tp        last_packet_recv;
		packet    w; // working packet we're constructing
		addrinfo* res;
		ms        timeout;
	};
}
