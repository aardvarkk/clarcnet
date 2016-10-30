#include "clarcnet.h"

#include <cassert>
#include <easylogging++.h>

using namespace std;

namespace clarcnet {

	const ver_t       ver_code = 0;
	const EVP_CIPHER* cipher_t = EVP_aes_128_ctr();

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
	
	#define xtostr(x) tostr(x)
	#define tostr(x)  #x

	#define thr \
	 	throw runtime_error(\
	 			string(__FILE__ ":" xtostr(__LINE__) " ") + string(strerror(errno)));

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
			throw runtime_error("Invalid intro byte!");
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
		ctx = EVP_CIPHER_CTX_new();
		fill(addr_str, addr_str + sizeof addr_str, 0);
	}
	
	conn_info::~conn_info()
	{
		EVP_CIPHER_CTX_free(ctx);
	}

	peer::peer() :
		fd(-1),
		lag_min(ms(0)),
		lag_max(ms(0))
	{
		random_device rdev;
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
		ps.erase(remove_if(
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
			uniform_int_distribution<> dist_lag(
					static_cast<int>(lag_min.count()),
					static_cast<int>(lag_max.count())
			);
			ms lag(dist_lag(rng));
			delayed.emplace_back(delayed_send(fd, move(p), clk::now() + lag));
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
		ps.emplace_back(move(ci.r.w));
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

					auto code = recv_into(fd, &r.w[r.recvd.v], min(r.w.size() - r.recvd.v, (r.req - r.recvd).v), r.recvd);
					if (code != SUCCESS) return code;

					if (r.recvd == r.req) {
						finish_packet(fd, ci, ps);
						break;
					}
				}
			}
		}
	}

	EVP_PKEY* server::load_key(bool is_public, std::string const& filename)
	{
		EVP_PKEY* key = nullptr;
		
		if (!filename.empty()) {
			auto fp = fopen(filename.c_str(), "r");
			if (fp) {
				key = is_public ?
					PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr) :
					PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
			}
			fclose(fp);
		}
		
		return key;
	}
	
	server::server(
		uint16_t port,
		string const& pubkeyfile,
		string const& prvkeyfile,
		ms heartbeat_period,
		ms timeout) :
		heartbeat_period(heartbeat_period),
		timeout(timeout)
	
	{
		public_key  = load_key(true,  pubkeyfile);
		private_key = load_key(false, prvkeyfile);
		cipher      = (public_key && private_key) ? cipher_t : EVP_enc_null();
		
		int err;
		addrinfo hints    = {}, *res;
		hints.ai_family   = AF_INET6;
		hints.ai_flags    = AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;

		stringstream port_ss;
		port_ss << port;
		if ((err = getaddrinfo(nullptr, port_ss.str().c_str(), &hints, &res)) != 0) {
			throw runtime_error(gai_strerror(err));
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
		err = ::bind(fd, res->ai_addr, res->ai_addrlen);
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

		auto code = peer::send(fd, move(p));
		return code;
	}

	ret_code server::process_initiated(int cfd, conn_info& ci, packets& in, packets& out)
	{
		LOG(DEBUG) << "process_initiated " << cfd;
		
		if (in.empty() || in.front().mid != ID_VERSION) return WAITING;
		
		packet resp(cfd, ID_VERSION);
		bool match = true;
		
		// TRANSITIONAL
		// TOOD: REMOVE
		if (in.front().size() == 6) {
			for (int i = 0; i < 6; ++i) {
				uint8_t maxver;
				in.front().srlz(false, maxver);
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
		else if (in.front().size() == sizeof(ver_t)) {
			ver_t ver_cl;
			in.front().srlz(false, ver_cl);
			match = ver_cl == ver_code;
			
			ver_t ver_sv = ver_code;
			resp.srlz(true, ver_sv);
		}
		// Unrecognized
		else {
			match = false;
		}
		
		in.erase(in.begin());
		send(cfd, move(resp));
		
		if (!match) {
			return FAILURE;
		} else {
			ci.st = conn_info::VERSIONED;
			
			// Send our public key for client to use (could be empty)
			packet pk(cfd, ID_CIPHER);

			uint8_t* serialized = nullptr;
			int sz = i2d_PUBKEY(public_key, &serialized);
			
			vector<uint8_t> pubkey;
			pubkey.insert(pubkey.begin(), serialized, serialized + sz);
			
			pk.srlz(true, pubkey);
			
			return send(cfd, move(pk));
		}
	}
	
	ret_code server::process_versioned(int cfd, conn_info& ci, packets& in, packets& out)
	{
		LOG(DEBUG) << "process_versioned " << cfd;
		
		if (in.empty() || in.front().mid != ID_CIPHER) return WAITING;
		
		vector<uint8_t> session_key_enc;
		vector<uint8_t> iv;
		in.front().srlz(false, session_key_enc);
		in.front().srlz(false, iv);
		
		int keys = EVP_OpenInit(
			ci.ctx,
			cipher,
			session_key_enc.data(),
			static_cast<int>(session_key_enc.size()),
			iv.data(),
			private_key
			);
		
		if (keys == 1) {
			ci.st = conn_info::SECURED;
			return SUCCESS;
		} else {
			return FAILURE;
		}
	}
	
	ret_code server::process_secured(int cfd, conn_info& ci, packets& in, packets& out)
	{
		LOG(DEBUG) << "process_secured " << cfd;
		
		ci.st = conn_info::CONNECTED;
		out.emplace_back(packet(cfd, ID_CONNECTION));
		return SUCCESS;
	}
	
	void server::process_accept()
	{
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
				
				conn_info& ci = conns[cfd];
				ci.st = conn_info::INITIATED;
				
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
	
	packets server::process(bool accept_new)
	{
		tp now = clk::now();
		
		flush_backlog();

		if (accept_new)
			process_accept();

		packets out;
		
		for (auto fd_to_ci = conns.begin(); fd_to_ci != conns.end();) {
			
			int        cfd  = fd_to_ci->first;
			conn_info& ci   = fd_to_ci->second;
			ret_code   code = SUCCESS;
			
			packets in;
			
			code = receive(cfd, ci, ci.st == conn_info::CONNECTED ? out : in);
			
			if (ci.st == conn_info::INITIATED) {
				code = process_initiated(cfd, ci, in, out);
			}
			
			if (code != FAILURE && ci.st == conn_info::VERSIONED) {
				code = process_versioned(cfd, ci, in, out);
			}
			
			if (code != FAILURE && ci.st == conn_info::SECURED) {
				code = process_secured(cfd, ci, in, out);
			}

			if (code != FAILURE && ci.st == conn_info::CONNECTED) {
				LOG(DEBUG) << "process_connected";
				out.insert(out.end(), in.begin(), in.end());
			}

			if (code == FAILURE) {
				if (ci.st == conn_info::CONNECTED) out.emplace_back(packet(cfd, ID_DISCONNECTION));
				fd_to_ci = disconnect(fd_to_ci);
				continue;
			} else {
				if (now - ci.last_packet_recv > timeout) {
					if (ci.st == conn_info::CONNECTED) out.emplace_back(packet(cfd, ID_TIMEOUT));
					fd_to_ci = disconnect(fd_to_ci);
					continue;
				}

				if (now - max(ci.last_heartbeat_sent, ci.last_packet_recv) >= heartbeat_period) {
					if (send(cfd, packet(cfd, ID_HEARTBEAT)) != SUCCESS) {
						if (ci.st == conn_info::CONNECTED) out.emplace_back(packet(cfd, ID_DISCONNECTION));
						fd_to_ci = disconnect(fd_to_ci);
						continue;
					}
					ci.last_heartbeat_sent = now;
				}
			}

			++fd_to_ci;
		}

		remove_heartbeats(out);
		
		return out;
	}

	string server::address(int cfd)
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

	client::client(string const& host, uint16_t port, ms timeout) :
		timeout(timeout)
	{
		conn_start = clk::now();
		ci.st = conn_info::DISCONNECTED;

		addrinfo hints    = {};
		hints.ai_family   = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		int err;

		stringstream port_ss;
		port_ss << port;
		if ((err = getaddrinfo(host.c_str(), port_ss.str().c_str(), &hints, &res)) != 0) {
			throw runtime_error(gai_strerror(err));
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

	void client::disconnect()
	{
		peer::close(fd);
		fd = -1;
		ci.st = conn_info::DISCONNECTED;
	}

	ret_code client::send(packet&& p)
	{
		return peer::send(this->fd, move(p));
	}

	ret_code client::process_disconnected()
	{
		LOG(DEBUG) << "process_disconnected";
		
		if (!poll_write()) return WAITING;
		
		ci.st = conn_info::INITIATED;
		
		inet_ntop(res->ai_family, in_addr(res->ai_addr), ci.addr_str, sizeof ci.addr_str);
		freeaddrinfo(res);
		res = nullptr;
		
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
		
		return send(move(version));
	}
	
	ret_code client::process_initiated(packets& in, packets& out)
	{
		LOG(DEBUG) << "process_initiated";
		
		if (in.empty() || in.front().mid != ID_VERSION) return WAITING;

		bool match = true;
		
		// TRANSITIONAL
		// TODO: REMOVE
		if (in.front().size() == 6) {
			uint8_t maxver;
			for (auto i = 0; i < 6; ++i) {
				in.front().srlz(false, maxver);
				if (maxver != 0xFF) {
					match = false;
					break;
				}
			}
		}
		// New approach
		else if (in.front().size() == sizeof(ver_t))
		{
			ver_t ver_sv;
			in.front().srlz(false, ver_sv);
			match = ver_sv == ver_code;
		}
		
		in.erase(in.begin());
		
		if (match) {
			ci.st = conn_info::VERSIONED;
			return SUCCESS;
		} else {
			out.push_back(packet(fd, ID_VERSION));
			return FAILURE;
		}
	}
	
	ret_code client::process_versioned(packets& in, packets& out)
	{
		LOG(DEBUG) << "process_versioned";
		
		if (in.empty() || in.front().mid != ID_CIPHER) return WAITING;
		
		vector<uint8_t> pubkey;
		in.front().srlz(false, pubkey);
		in.erase(in.begin());
		
		bool success = true;
		vector<uint8_t> session_key_enc, iv;
		
		if (!pubkey.empty()) {
			const uint8_t* data = pubkey.data();
			auto pkey = d2i_PUBKEY(nullptr, &data, pubkey.size());
			
			session_key_enc.resize(EVP_PKEY_size(pkey));
			iv.resize(EVP_CIPHER_iv_length(cipher_t));

			auto session_key_enc_data = session_key_enc.data();
			int  session_key_enc_lens[1] = { 0 };
			
			int npubk = EVP_SealInit(
				ci.ctx,
				cipher_t,
				&session_key_enc_data,
				session_key_enc_lens,
				iv.data(),
				&pkey,
				1
			);
			
			success = npubk == 1;
		}
		
		if (success) {
			ci.st = conn_info::SECURED;
			
			packet session(fd, ID_CIPHER);
			session.srlz(true, session_key_enc);
			session.srlz(true, iv);
			
			return send(move(session));
		} else {
			return FAILURE;
		}
	}
	
	ret_code client::process_secured(packets& in, packets& out)
	{
		LOG(DEBUG) << "process_secured";
		
		ci.st = conn_info::CONNECTED;
		out.push_back(packet(fd, ID_CONNECTION));
		
		return SUCCESS;
	}
	
	packets client::process()
	{
		packets  in, out;
		ret_code code = SUCCESS;

		flush_backlog();
		
		if (fd < 0) return out;
		
		code = receive(fd, ci, ci.st == conn_info::CONNECTED ? out : in);
		
		if (ci.st == conn_info::DISCONNECTED) {
			code = process_disconnected();
		}
		
		if (ci.st == conn_info::INITIATED) {
			code = process_initiated(in, out);
		}
		
		if (code != FAILURE && ci.st == conn_info::VERSIONED) {
			code = process_versioned(in, out);
		}
		
		if (code != FAILURE && ci.st == conn_info::SECURED) {
			code = process_secured(in, out);
		}

		if (code != FAILURE && ci.st == conn_info::CONNECTED) {
			LOG(DEBUG) << "process_connected";
			out.insert(out.begin(), in.begin(), in.end());
		}
		
		if (code == FAILURE) {
			ci.st = conn_info::DISCONNECTED;
			out.emplace_back(packet(fd, ID_DISCONNECTION));
			return out;
		}

		for (auto const& p : out) {
			if (p.mid != ID_HEARTBEAT) continue;
			if (send(packet(p)) != SUCCESS) {
				ci.st = conn_info::DISCONNECTED;
				out.emplace_back(packet(fd, ID_DISCONNECTION));
				return out;
			}
		}

		if (timeout != ms(0) && clk::now() - ci.last_packet_recv > timeout) {
			out.emplace_back(packet(fd, ID_TIMEOUT));
			return out;
		}

		remove_heartbeats(out);
		
		return out;
	}

	string client::address()
	{
		return ci.addr_str;
	}
}
