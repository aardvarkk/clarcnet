#include "clarcnet.h"

#include <cassert>

namespace clarcnet {

	const ver_t ver_code = 0;

	void* in_addr(sockaddr* sa) {
		switch (sa->sa_family) {
			case AF_INET  :
				return &((sockaddr_in*) sa)->sin_addr ;
				
			case AF_INET6 :
				return &((sockaddr_in6*)sa)->sin6_addr;
				
			default       :
				return nullptr;
		}
	}
	
	#define tostr(x) #x

	#define thr \
	 	throw std::runtime_error(\
	 			std::string(tostr(__FILE__) ":" tostr(__LINE__) " ") + std::string(strerror(errno)));

	#define chk(val) \
	{\
		if (val < 0) {\
			thr;\
		}\
	}

	delayed_send::delayed_send() :
		delayed_send(-1, packet(),
		clk::now())
	{
	}
	
	delayed_send::delayed_send(int fd, packet&& p, tp const& earliest) :
		fd(fd),
		p(p),
		earliest(earliest)
	{
	}

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

	receive_state::receive_state() :
		state(MessageID),
		recvd(0),
		req(1)
	{
		w.resize(1 + header_bytes_req(0xFE)); // request maximum header size
	}

	conn_info::conn_info() :
		last_packet_recv(clk::now()),
		st(UNKNOWN)
	{
		std::fill(addr_str, addr_str + sizeof addr_str, 0);
	}

	peer::peer() :
		fd(-1),
		lag_min(ms(0)),
		lag_max(ms(0))
	{
		std::random_device rdev;
		rng.seed(rdev());
	}

	ret_code peer::close(int fd)
	{
		int err = ::close(fd);
		chk(err);
		return SUCCESS;
	}

	// Don't pass along heartbeats -- they're internal
	void peer::remove_heartbeats(packets& ps)
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
	bool peer::poll_write()
	{
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

	ret_code peer::send_sock(int fd, void const* data, size_t sz)
	{
		if (sz == 0) return SUCCESS;

		size_t sent = 0;

		while (sent < sz) {
			auto len = ::send(fd, data, sz - sent, 0);

			if (len > 0) sent += len;

			if (sent == sz) {
				return SUCCESS;
			}
			else if (len == 0) {
				return FAILURE;
			}
			else if (len < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					poll_write();
				}
				else if (errno == ECONNRESET || errno == EPIPE) {
					return FAILURE;
				}
				else {
					thr;
				}
			}
		}

		return FAILURE;
	}

	ret_code peer::send_packet(int fd, packet &p)
	{
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

	void peer::flush_backlog() {
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

	ret_code peer::send(int fd, packet&& p)
	{
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

	ret_code peer::recv_into(int fd, void* buffer, len_t bytes, len_t& recvd)
	{
		if (!bytes.v) return SUCCESS;

		// Try to retrieve exactly the number required
		ssize_t len = recv(fd, buffer, bytes.v, 0);

		// Mark the new size since we've received bytes
		if (len > 0) recvd += len;

		if (len == bytes.v) {
			return SUCCESS;
		}
		else if (len == 0) {
			return FAILURE;
		}
		else if (len > 0) {
			return WAITING;
		}
		else {
			if (errno == ECONNRESET || errno == ETIMEDOUT) {
				return FAILURE;
			}
			else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return WAITING;
			} else {
				thr;
			}
		}
	}

	void peer::finish_packet(int fd, conn_info &ci, packets &ps)
	{
		assert(fd > 0);
		assert(ci.r.recvd == ci.r.req);
		ci.r.w.rpos = 0;
		ci.r.w.resize(ci.r.req.v);
		ci.r.w.fd = fd;
		ps.emplace_back(std::move(ci.r.w));
		ci.r = receive_state();
		ci.last_packet_recv = clk::now();
	}

	ret_code peer::receive(int fd, conn_info &ci, packets &ps)
	{

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

	server::server(uint16_t port, ms heartbeat_period, ms timeout)
	{
		this->heartbeat_period = heartbeat_period;
		this->timeout = timeout;
		int err;
		addrinfo hints    = {}, *res;
		hints.ai_family   = AF_INET6;
		hints.ai_flags    = AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;

		std::stringstream port_ss;
		port_ss << port;
		if ((err = getaddrinfo(nullptr, port_ss.str().c_str(), &hints, &res)) != 0) {
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

	server::~server()
	{
		for (auto it = conns.begin(); it != conns.end(); ++it) {
			close(it->first);
		}
		::close(fd);
	}
		
	ret_code server::send(int fd, packet&& p)
	{
		auto it = conns.find(fd);
		if (it == conns.end()) return FAILURE;

		auto code = peer::send(fd, std::move(p));
		return code;
	}

	packets server::process(bool accept_new)
	{
		tp now = clk::now();
		
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
					
					conn_info ci;
					ci.st = conn_info::INITIATED;
					conns.insert(std::make_pair(cfd, ci));

					inet_ntop(client.ss_family, in_addr((sockaddr*)&client), conns[cfd].addr_str, sizeof conns[cfd].addr_str);
					int err = fcntl(cfd, F_SETFL, O_NONBLOCK);
					chk(err);
					
					#ifdef SO_NOSIGPIPE
					socklen_t val = 1;
					err = setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof val);
					chk(err);
					#endif
				}
			}
		}

		for (auto fd_to_ci = conns.begin(); fd_to_ci != conns.end();) {
			
			int        cfd  = fd_to_ci->first;
			conn_info& ci   = fd_to_ci->second;
			ret_code   code = SUCCESS;
			
			// server
			switch (ci.st)
			{
				case conn_info::INITIATED:
				{
					packets version;
					code = receive(cfd, ci, version);
					if (!version.empty()) {
					
						packet resp(cfd, ID_VERSION);
						
						bool match = true;
						
						// TOOD: REMOVE
						// TRANSITIONAL
						if (version.front().size() == 6) {
							for (int i = 0; i < 6; ++i) {
								uint8_t maxver;
								version.front().srlz(false, maxver);
								if (maxver != 0xFF) {
									match = false;
									break;
								}
							}
							
							resp.push_back(0xFF); resp.push_back(0xFF);
							resp.push_back(0xFF); resp.push_back(0xFF);
							resp.push_back(0xFF); resp.push_back(0xFF);
						}
						// New approach
						else if (version.front().size() == sizeof(ver_t)) {
							ver_t ver_cl;
							version.front().srlz(false, ver_cl);
							match = ver_cl == ver_code;
							
							ver_t ver_sv = ver_code;
							resp.srlz(true, ver_sv);
						}
						// Unrecognized
						else {
							match = false;
						}
						
						send(cfd, std::move(resp));
						
						if (!match) {
							code = FAILURE;
						} else {
							ci.st = conn_info::VERSIONED;
						}
					}
				}
				break;
				
				case conn_info::VERSIONED:
				{
					// TODO: encryption
					ci.st = conn_info::SECURED;
				}
				break;
				
				case conn_info::SECURED:
				{
					ci.st = conn_info::CONNECTED;
					ret.emplace_back(packet(cfd, ID_CONNECTION));
				}
				break;
				
				case conn_info::CONNECTED:
				{
					code = receive(cfd, ci, ret);
				}
				break;
				
				// Invalid connection state
				default:
				{
					code = FAILURE;
				}
				break;
			}
			
			if (code == FAILURE) {
				if (ci.st == conn_info::CONNECTED) ret.emplace_back(packet(cfd, ID_DISCONNECTION));
				fd_to_ci = disconnect(fd_to_ci);
				continue;
			} else {
				if (now - ci.last_packet_recv > timeout) {
					if (ci.st == conn_info::CONNECTED) ret.emplace_back(packet(cfd, ID_TIMEOUT));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
				}

				if (now - max(ci.last_heartbeat_sent, ci.last_packet_recv) >= heartbeat_period) {
					if (send(cfd, packet(cfd, ID_HEARTBEAT)) != SUCCESS) {
						if (ci.st == conn_info::CONNECTED) ret.emplace_back(packet(cfd, ID_DISCONNECTION));
						fd_to_ci = disconnect(fd_to_ci);
						continue;
					}
					ci.last_heartbeat_sent = now;
				}
			}

			++fd_to_ci;
		}

		remove_heartbeats(ret);
		return ret;
	}

	std::string server::address(int cfd)
	{
		auto fd_to_ci = conns.find(cfd);
		return fd_to_ci == conns.end() ? "" : fd_to_ci->second.addr_str;
	}

	// External disconnect -- called by others
	// Since they pass a file descriptor, we know we can close it and reuse it since they should be done with it
	void server::disconnect(int cfd)
	{
		auto conn_it = conns.find(cfd);
		if (conn_it != conns.end()) disconnect(conn_it);
		peer::close(cfd);
	}

	// Internal disconnect -- called when we determine a client has disconnected or inactive
	server::conn_map::iterator server::disconnect(server::conn_map::iterator conn_it)
	{
		int cfd = conn_it->first;
		delayed.erase(remove_if(delayed.begin(), delayed.end(),
		[=](delayed_send const& ds) {
			return ds.fd == cfd;
		}), delayed.end());
		return conns.erase(conn_it);
	}

	client::client(std::string const& host, uint16_t port, ms timeout) :
		timeout(timeout)
	{
		conn_start = clk::now();

		addrinfo hints    = {};
		hints.ai_family   = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		int err;

		std::stringstream port_ss;
		port_ss << port;
		if ((err = getaddrinfo(host.c_str(), port_ss.str().c_str(), &hints, &res)) != 0) {
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

		ci.st = conn_info::INITIATING;
	}

	void client::disconnect()
	{
		peer::close(fd);
		fd = -1;
		ci.st = conn_info::DISCONNECTED;
	}

	ret_code client::send(packet&& p)
	{
		return peer::send(this->fd, std::move(p));
	}

	packets client::process()
	{
		packets  ret;
		ret_code code = SUCCESS;

		flush_backlog();
		
		if (fd < 0) return ret;

		// client
		switch (ci.st) {
			case conn_info::INITIATING:
			{
				if (!poll_write()) break;
				
				inet_ntop(res->ai_family, in_addr(res->ai_addr), ci.addr_str, sizeof ci.addr_str);
				freeaddrinfo(res);
				res = nullptr;
				
				code  = SUCCESS;
				ci.st = conn_info::INITIATED;
			}
			break;
			
			case conn_info::INITIATED:
			{
				packet version(fd, ID_VERSION);
				
				// TRANSITIONAL
				// Send a 6-byte old-style version
				// Old server will see we're too new and forward us
				// New server will detect we're using old approach and allow it
				if (true) {
					uint8_t maxver = 0xFF;
					version.srlz(true, maxver); version.srlz(true, maxver);
					version.srlz(true, maxver); version.srlz(true, maxver);
					version.srlz(true, maxver); version.srlz(true, maxver);
				}
				else {
					// New approach...
					ver_t ver_cl = ver_code;
					version.srlz(true, ver_cl);
				}
				
				code  = send(std::move(version));
				ci.st = conn_info::VERSIONING;
			}
			break;
			
			case conn_info::VERSIONING:
			{
				packets version;
				code = receive(fd, ci, version);

				if (version.empty()) break;

				bool match = true;
				
				// TRANSITIONAL
				if (version.front().size() == 6) {
					uint8_t maxver;
					for (auto i = 0; i < 6; ++i) {
						version.front().srlz(false, maxver);
						if (maxver != 0xFF) {
							match = false;
							break;
						}
					}
				}
				// New approach
				else if (version.front().size() == sizeof(ver_t))
				{
					ver_t ver_sv;
					version.front().srlz(false, ver_sv);
					match = ver_sv == ver_code;
				}
				
				// Something went wrong!
				if (match) {
					ci.st = conn_info::VERSIONED;
				} else {
					ret.push_back(packet(fd, ID_VERSION));
				}
			}
			break;
	
			case conn_info::VERSIONED:
			{
				ci.st = conn_info::SECURING;
			}
			break;
			
			case conn_info::SECURING:
			{
				ci.st = conn_info::SECURED;
			}
			break;
			
			case conn_info::SECURED:
			{
				ci.st = conn_info::CONNECTED;
				ret.push_back(packet(fd, ID_CONNECTION));
			}
			break;
			
			case conn_info::CONNECTED:
			{
				code = receive(fd, ci, ret);
			}
			break;
			
			// Invalid connection state
			default:
			{
				code = FAILURE;
			}
			break;
		}
		
		if (code == FAILURE) {
			ci.st = conn_info::DISCONNECTED;
			ret.emplace_back(packet(fd, ID_DISCONNECTION));
			return ret;
		}

		for (auto const& p : ret) {
			if (p.mid != ID_HEARTBEAT) continue;
			if (send(packet(p)) != SUCCESS) {
				ci.st = conn_info::DISCONNECTED;
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

	std::string client::address()
	{
		return ci.addr_str;
	}
}
