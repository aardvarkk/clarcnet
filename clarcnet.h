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
	
	struct len_t {
		len_t() : v(0) {}
		len_t(uint64_t l) : v(l) {}
		
		bool   operator==(len_t const& l) { return v == l.v; }
		len_t& operator+=(len_t const& l) { v += l.v; return *this; }
		len_t  operator- (len_t const& l) { return v - l.v; }
		
		uint64_t v;
	};

	enum ret_code
	{
		SUCCESS,
		FAILURE,
		DISCONNECTED,
		WAITING
	};

	struct streambuffer : std::vector<uint8_t> {
		int rpos;    // current reading position
		int binplcs; // number of binary decimal places for read/write floating point

		streambuffer() : rpos(0), binplcs(16) {}

		template <typename T>
		void srlz(bool w, T& val);
	};

	template <>
	inline void streambuffer::srlz(bool w, uint8_t& val)
	{
		if (w) {
			push_back(val);
		} else {
			val = this->operator[](rpos);
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, bool& val)
	{
		if (w) {
			push_back(val);
		} else {
			val = this->operator[](rpos);
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, uint16_t& val)
	{
		if (w) {
			uint16_t vn = htons(val);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof val);
		} else {
			val = ntohs(*reinterpret_cast<uint16_t*>(&this->operator[](rpos)));
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, uint32_t& val)
	{
		if (w) {
			uint32_t vn = htonl(val);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof val);
		} else {
			val = ntohl(*reinterpret_cast<uint32_t*>(&this->operator[](rpos)));
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, uint64_t& val)
	{
		if (w) {
			#ifdef __linux
			uint64_t vn = htobe64(val);
			#else
			uint64_t vn = htonll(val);
			#endif
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof val);
		} else {
			#ifdef __linux
			val = be64toh(*reinterpret_cast<uint64_t*>(&this->operator[](rpos)));
			#else
			val = ntohll (*reinterpret_cast<uint64_t*>(&this->operator[](rpos)));
			#endif
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, float& val)
	{
		if (w) {
			int32_t ival = val * (1<<binplcs);
			srlz(w, ival);
		} else {
			int32_t ival;
			srlz(w, ival);
			val = static_cast<float>(ival) / (1<<binplcs);
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, len_t& val)
	{
		if (w) {
			if (val.v <= 0xFA) {
				uint8_t v = val.v;
				srlz(w, v);
			}
			else if (val.v <= UINT8_MAX) {
				uint8_t intro = 0xFB;
				srlz(w, intro);
				uint8_t v = static_cast<uint8_t>(val.v);
				srlz(w, v);
			}
			else if (val.v <= UINT16_MAX) {
				uint8_t intro = 0xFC;
				srlz(w, intro);
				uint16_t v = static_cast<uint16_t>(val.v);
				srlz(w, v);
			}
			else if (val.v <= UINT32_MAX) {
				uint8_t intro = 0xFD;
				srlz(w, intro);
				uint32_t v = static_cast<uint32_t>(val.v);
				srlz(w, v);
			}
			else if (val.v <= UINT64_MAX) {
				uint8_t intro = 0xFE;
				srlz(w, intro);
				srlz(w, val.v);
			} else {
				throw std::runtime_error("Invalid size!");
			}
		} else {
			uint8_t intro;
			srlz(w, intro);

			if (intro <= 0xFA) {
				val.v = intro;
			}
			else if (intro == 0xFB) {
				uint8_t v;
				srlz(w, v);
				val.v = v;
			}
			else if (intro == 0xFC) {
				uint16_t v;
				srlz(w, v);
				val.v = v;
			}
			else if (intro == 0xFD) {
				uint32_t v;
				srlz(w, v);
				val.v = v;
			}
			else if (intro == 0xFE) {
				uint64_t v;
				srlz(w, v);
				val.v = v;
			}
			else {
				throw std::runtime_error("Invalid size!");
			}
		}
	}

	// Default fall-through for enum types
	template <typename T>
	inline void streambuffer::srlz(bool w, T& val)
	{
		len_t l(val);
		srlz(w, l);
		val = static_cast<T>(l.v);
	}
	
	template <>
	inline void streambuffer::srlz(bool w, std::string& val)
	{
		if (w) {
			len_t l(val.size());
			srlz(w, l);
			insert(end(), val.begin(), val.end());
		} else {
			len_t l;
			srlz(w, l);
			
			uint8_t* p = &this->operator[](rpos);
			val = std::string(p, p + l.v);
			rpos += l.v;
		}
	}
	
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
		len_t  recvd; // bytes received while in this state
		len_t  req;   // bytes required to exit this state
		packet w;     // working packet to receive into
	};

	struct conn_info {
		conn_info() : last_packet_recv(clk::now())
		{
			std::fill(addr_str, addr_str + sizeof addr_str, 0);
		}

		char          addr_str[INET6_ADDRSTRLEN];
		receive_state r;
		tp            last_packet_recv;    // force timeout of client if they haven't responded
		tp            last_heartbeat_sent; // know when to send more heartbeats
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
			len_t l(p.size());
			header.srlz(true, l);
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

		ret_code recv_into(int fd, void* buffer, len_t bytes, len_t& recvd) {
			if (!bytes.v) return SUCCESS;

			// Try to retrieve exactly the number required
			ssize_t len = recv(fd, buffer, bytes.v, 0);

			// Mark the new size since we've received bytes
			if (len > 0) recvd += len;

			if (len == bytes.v) {
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

		void finish_packet(int fd, conn_info &ci, packets &ps) {
			assert(fd > 0);
			assert(ci.r.recvd == ci.r.req);
			ci.r.w.rpos = 0;
			ci.r.w.resize(ci.r.req.v);
			ci.r.w.fd = fd;
			ps.emplace_back(std::move(ci.r.w));
			ci.r = receive_state();
			ci.last_packet_recv = clk::now();
		}

		// peer
		ret_code receive(int fd, conn_info &ci, packets &ps) {

			receive_state& r = ci.r;

			// Keep going while we are receiving packets!
			for (;;) {

				if (r.state == receive_state::MessageID) {
					auto code = recv_into(fd, &r.w.mid, r.req - r.recvd, r.recvd);
					if (code != SUCCESS) return code;

					// If the message is a heartbeat, we're done!
					if (r.w.mid == ID_HEARTBEAT) {
						finish_packet(fd, ci, ps);
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
					auto code = recv_into(fd, &r.w[r.recvd.v], r.req - r.recvd, r.recvd);
					if (code != SUCCESS) return code;

					r.state = receive_state::Payload;
					r.recvd = 0;
					
					r.w.srlz(false, r.req);
				}

				if (r.state == receive_state::Payload) {

					for (;;) {

						// allocate more space as necessary
						// but don't resize directly to client request because they could make us allocate tons of memory!
						if (r.w.size() < r.req.v) r.w.resize(r.w.size() * 2);

						auto code = recv_into(fd, &r.w[r.recvd.v], std::min(r.w.size() - r.recvd.v, (r.req - r.recvd).v), r.recvd);
						if (code != SUCCESS) return code;

						if (r.recvd == r.req) {
							finish_packet(fd, ci, ps);
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
			res = nullptr;
		}

		~server() {
			for (auto it = conns.begin(); it != conns.end(); ++it) {
				close(it->first);
			}
			close(fd);
		}
		
		ret_code send(int fd, packet&& p) {
			auto it = conns.find(fd);
			if (it == conns.end()) return FAILURE;

			auto code = peer::send(fd, std::move(p));
			return code;
		}

		// server
		packets process(bool accept_new = true) {
			flush_backlog();
			packets ret;

			if (accept_new) {
				for (;;) {
					sockaddr_storage client;
					socklen_t sz = sizeof client;
					int cfd = accept(fd, (sockaddr*)&client, &sz);

					if (cfd < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							break;
						} else {
							thr;
						}
					} else {
						assert(!conns.count(cfd));
						conns.insert(std::make_pair(cfd, conn_info()));
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
				conn_info& ci = fd_to_ci->second;

				auto code = receive(cfd, ci, ret);

				if (code == DISCONNECTED) {
					ret.emplace_back(packet(cfd, ID_DISCONNECTION));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
				} else {
					if (now - ci.last_packet_recv > timeout) {
						ret.emplace_back(packet(cfd, ID_TIMEOUT));
						fd_to_ci = disconnect(fd_to_ci);
						continue;
					}

					if (now - max(ci.last_heartbeat_sent, ci.last_packet_recv) >= heartbeat_period) {
						if (send(cfd, packet(cfd, ID_HEARTBEAT)) != SUCCESS) {
							ret.emplace_back(packet(cfd, ID_DISCONNECTION));
							fd_to_ci = disconnect(fd_to_ci);
							continue;
						}
						ci.last_heartbeat_sent = now;
					}
				}

				++fd_to_ci;
			}

			// TEMP: Deal with old versions
			// Anybody who sent unknown, respond with OLD version style
			for (auto const& p : ret) {
				if (p.mid == ID_UNKNOWN) {
					const unsigned char data[] = { 0x00, 0x00, 0x00, 0x0B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
					send_sock(p.fd, data, 11);
				}
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

		typedef std::unordered_map<int, conn_info> conn_map;

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
		client(std::string const& host, uint16_t port, ms timeout = ms(0)) {
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

				inet_ntop(res->ai_family, in_addr(res->ai_addr), ci.addr_str, sizeof ci.addr_str);
				freeaddrinfo(res);
				res = nullptr;

				connected = true;
				ret.emplace_back(packet(fd, ID_CONNECTION));
				return ret;
			}

			auto code = receive(fd, ci, ret);

			if (code == DISCONNECTED) {
				ret.emplace_back(packet(fd, ID_DISCONNECTION));
				return ret;
			}
		
			for (auto const& p : ret) {
				if (p.mid != ID_HEARTBEAT) continue;
				if (send(packet(p)) != SUCCESS) {
					ret.emplace_back(packet(fd, ID_DISCONNECTION));
					return ret;
				}
			}

			if (timeout != ms(0) && clk::now() - ci.last_packet_recv > timeout) {
				ret.emplace_back(packet(fd, ID_TIMEOUT));
				return ret;
			}
			
			remove_heartbeats(ret);
			return ret;
		}

		std::string address() {
			return ci.addr_str;
		}

	protected:
		tp        conn_start;
		bool      connected;
		conn_info ci;
		addrinfo* res;
		ms        timeout;
	};
}
