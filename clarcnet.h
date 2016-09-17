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

	static const char* _msg_strs[] = {
		"ID_UNKNOWN",
		"ID_CONNECTION",
		"ID_DISCONNECTION",
		"ID_TIMEOUT",
		"ID_HEARTBEAT",
		"ID_USER"
	};

	typedef std::vector<uint8_t>               buffer;
	typedef std::chrono::high_resolution_clock clk;
	typedef std::chrono::milliseconds          ms;
	typedef std::chrono::time_point<clk>       tp;

//	static size_t header_bytes_req(size_t payload_sz) {
//		if      (payload_sz <= 0xFA      ) return 1;
//		else if (payload_sz <= UINT8_MAX ) return 2;
//		else if (payload_sz <= UINT16_MAX) return 3;
//		else if (payload_sz <= UINT32_MAX) return 5;
//		else if (payload_sz <= UINT64_MAX) return 9;
//		else                               return 0;
//	}

	// returns total header size (INCLUDING intro byte) required based on the intro byte itself
	static size_t header_bytes_req(uint8_t intro) {
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

	struct streambuffer : buffer {
		int rpos;
		size_t recvd;

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
		msg_id       mid;
		streambuffer header;
		
		packet() : fd(-1), mid(ID_UNKNOWN) {}
		packet(msg_id mid) : fd(-1), mid(mid) {}
		packet(int fd, msg_id mid) : fd(fd), mid(mid) {}
		
		void set_header() {
			header.clear();
			header.w_size_t(size());
		}
	};

	typedef std::vector<packet> packets;

	struct client_info {
	public:
		client_info() :
			last_packet_sent(clk::now()),
			last_packet_recv(clk::now())
		{
			std::fill(addr_str, addr_str + sizeof addr_str, 0);
		}

		char         addr_str[INET6_ADDRSTRLEN];
		streambuffer b;
		tp           last_packet_sent;
		tp           last_packet_recv;
	};

	typedef std::unordered_map<int, client_info> conn_map;
	
	struct delayed_send {
		delayed_send() : fd(-1), earliest(clk::now()) {}
		int    fd;
		packet p;
		tp     earliest;
	};

	enum ret_code {
		SUCCESS,
		FAILURE,
		DISCONNECTED,
		WAITING
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

	std::deque<delayed_send> send_backlog;

	// Blocking wait to write
//	void wait_write() {
//		fd_set writable;
//		FD_ZERO(&writable);
//		FD_SET(fd, &writable);
//
//		int err = select(1, nullptr, &writable, nullptr, nullptr);
//		assert(err == 1);
//	}

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

	private:
		
		std::default_random_engine rng;

		ret_code send_sock(int fd, void const* data, size_t sz) {
			size_t sent = 0;

			assert(sz);

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
					else if (errno == ECONNRESET) {
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

			// Set the header data for the packet
			p.set_header();

			p.header.rpos = 0;
			assert(p.size() == p.header.r_size_t());

			// Header
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
				case AF_INET  : return &((sockaddr_in*) sa)->sin_addr ;
				case AF_INET6 : return &((sockaddr_in6*)sa)->sin6_addr;
				default       : return nullptr;
			}
		}

		void flush_backlog() {
			auto now = clk::now();
			while (!send_backlog.empty()) {
				if (send_backlog.front().earliest > now) break;
				
				delayed_send ds = send_backlog.front();
				ret_code code = send_packet(ds.fd, ds.p);
				if (code != SUCCESS) {
					break;
				}
				
				send_backlog.pop_front();
			}
		}

		ret_code send(int fd, packet& p) {
			if (!lag_max.count()) {
				return send_packet(fd, p);
			} else {
				
				std::uniform_int_distribution<> dist_lag(
					static_cast<int>(lag_min.count()),
					static_cast<int>(lag_max.count())
				);
				ms lag(dist_lag(rng));
				
				delayed_send ds;
				ds.fd       = fd;
				ds.p        = p;
				ds.earliest = clk::now() + lag;
				send_backlog.push_back(ds);
				
				return SUCCESS;
			}
		}

		ret_code recv_into(int fd, streambuffer& b, size_t bytes) {

			// Expand as we receive more data
			if (b.size() < b.recvd + bytes) b.resize(b.recvd + bytes);

			// Try to retrieve exactly the number required
			ssize_t len = recv(fd, &*(b.begin() + b.recvd), bytes, 0);

			// Mark the new size since we've received bytes
			if (len > 0) b.recvd += len;

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

		void finish_packet(streambuffer &b, size_t bytes) {
			assert(!b.empty());
			assert(bytes);
			assert(b.size() >= bytes);
			assert(b.recvd >= bytes);
			b.erase(b.begin(), b.begin() + bytes);
			b.recvd -= bytes;
			assert(b.size() >= b.recvd);
		}

		ret_code receive(int fd, streambuffer& b, packets& ps) {

			int i = 0;

			// Keep going while we are receiving packets!
			for (;;) {

				++i;

				ret_code test = DISCONNECTED;

				// Step 1 -- get the intro byte
				if (!b.recvd) {
					auto code = recv_into(fd, b, 1);
					test = code;
					if (code != SUCCESS) {
						return code;
					}
				}

				assert(b.front() != 0);
				assert(b.front() >= 60);

				// Step 2 -- if the intro is a heartbeat, we're done!
				if (b.front() == 0xFF) {
					ps.push_back(packet(fd, ID_HEARTBEAT));
					finish_packet(b, 1);
					continue;
				}

				// Step 3 -- get the rest of the header
				auto header_sz_req = header_bytes_req(b.front());
				if (b.recvd < header_sz_req) {
					auto code = recv_into(fd, b, header_sz_req - b.recvd);
					if (code != SUCCESS) {
						assert(b.front() != 0);
						assert(b.front() >= 60);
						return code;
					}
				}

				// Step 4 -- get the message ID
				auto header_and_mid_sz_req = header_sz_req + 1;
				if (b.recvd < header_and_mid_sz_req) {
					auto code = recv_into(fd, b, header_and_mid_sz_req - b.recvd);
					if (code != SUCCESS) {
						assert(b.front() != 0);
						return code;
					}
				}

				// Step 5 -- get the payload
				b.rpos = 0;
				auto payload_sz = b.r_size_t();

				assert(payload_sz > 60);

				if (b.recvd < header_and_mid_sz_req + payload_sz) {
					auto code = recv_into(fd, b, header_and_mid_sz_req + payload_sz - b.recvd);
					if (code != SUCCESS) {
						assert(b.front() != 0);
						return code;
					}
				}

				// We have a packet! Grab what we need and continue
				b.rpos = 0;
				payload_sz = b.r_size_t();
				msg_id mid = static_cast<msg_id>(b.r_int8_t());

				packet p(fd, mid);

				assert(b.recvd >= header_and_mid_sz_req + payload_sz);
				assert(b.size() >= header_and_mid_sz_req + payload_sz);

				p.header.insert(p.header.begin(), b.begin(), b.begin() + header_sz_req);
				p.insert(p.begin(), b.begin() + header_and_mid_sz_req, b.begin() + header_and_mid_sz_req + payload_sz);

				assert(p.header.size() == header_sz_req);
				assert(p.size() == payload_sz);

				p.header.rpos = 0;
				assert(p.size() == p.header.r_size_t());

				ps.push_back(p);

				// Finished up with this packet
				// Push the data back to the start of the buffer so we can examine from the front
				finish_packet(b, header_and_mid_sz_req + payload_sz);

				assert(b.front() != 0);
				assert(b.front() >= 60);
			}
		}
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

			inet_ntop(res->ai_family, in_addr(res->ai_addr), addr_str, sizeof addr_str);

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

		ret_code send(int fd, packet &p) {
			if (!conns.count(fd)) return FAILURE;
			return peer::send(fd, p);
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

//				if (now - ci.last_packet_sent >= heartbeat_period) {
//					packet heartbeat = packet(cfd, ID_HEARTBEAT);
//					if (send(cfd, heartbeat) != SUCCESS) {
//						disconnect(cfd);
//						continue;
//					}
//					ci.last_packet_sent = now;
//				}

				auto code = receive(cfd, ci.b, ret);
				switch (code) {
					case DISCONNECTED:
					{
						fd_to_ci = disconnect(fd_to_ci);
						ret.push_back(packet(cfd, ID_DISCONNECTION));
					}
					continue;

					default:
					break;
				}

				if (!ret.empty())
					ci.last_packet_recv = now;

				if (now - ci.last_packet_recv > timeout) {
					ret.push_back(packet(cfd, ID_TIMEOUT));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
				}

				ret.erase(std::remove_if(
					ret.begin(),
					ret.end(),
					[](packet const& p) { return p.mid == ID_HEARTBEAT; }
					), ret.end());

				++fd_to_ci;
			}

			return ret;
		}

		std::string address(int cfd) { auto fd_to_ci = conns.find(cfd); return fd_to_ci == conns.end() ? "" : fd_to_ci->second.addr_str; }

		char addr_str[INET6_ADDRSTRLEN];

		void disconnect(int cfd) {
			auto it = conns.find(cfd);
			if (it == conns.end()) return;
			disconnect(it);
		}
		
	protected:
		conn_map conns;
		ms       heartbeat_period;
		ms       timeout;

		conn_map::iterator disconnect(conn_map::iterator conn_it) {
			int cfd = conn_it->first;
			send_backlog.erase(remove_if(send_backlog.begin(), send_backlog.end(),
				[=](delayed_send const& ds) {
					return ds.fd == cfd;
				}), send_backlog.end());
			close(conn_it->first);
			return conns.erase(conn_it);
		}
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

		ret_code send(packet &p) {
			return peer::send(this->fd, p);
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
						ret.push_back(packet(fd, ID_TIMEOUT));
						return ret;
					}
				}

				if (!poll_write()) return ret;

				connected = true;

				freeaddrinfo(res);

				ret.push_back(packet(fd, ID_CONNECTION));

				return ret;
			}

			auto code = receive(fd, b, ret);
			switch (code) {
				case DISCONNECTED:
				{
					ret.push_back(packet(fd, ID_DISCONNECTION));
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
				packet resp(p);
				if (send(resp) != SUCCESS) {
					ret.push_back(packet(fd, ID_DISCONNECTION));
					disconnect();
					return ret;
				}
			}

			if (timeout != ms(0) && clk::now() - last_packet_recv > timeout) {
				ret.push_back(packet(fd, ID_TIMEOUT));
				disconnect();
			}

			ret.erase(std::remove_if(
				ret.begin(),
				ret.end(),
				[](packet const& p) { return p.mid == ID_HEARTBEAT; }
				), ret.end());

			return ret;
		}

	protected:
		tp           conn_start;
		bool         connected;
		tp           last_packet_recv;
		streambuffer b;
		addrinfo*    res;
		ms           timeout;
	};
}
