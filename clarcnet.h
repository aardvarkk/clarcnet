#pragma once

#include <arpa/inet.h>
#include <chrono>
#include <deque>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/pem.h>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <sys/poll.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace clarcnet {

	typedef int8_t  ver_t;
	const   ver_t   ver_code = 1;
	const   uint8_t ver_transition = 0x11;

	enum msg_id : uint8_t {
		ID_UNKNOWN,
		ID_VERSION,
		ID_CIPHER,
		ID_CONNECTION,
		ID_DISCONNECTION,
		ID_HEARTBEAT,
		ID_TIMEOUT,
		ID_USER
	};

	static const char* msg_strs[ID_USER+1] = {
		"ID_UNKNOWN",
		"ID_VERSION",
		"ID_CIPHER",
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
		WAITING
	};

	struct streambuffer : std::vector<uint8_t> {
		int rpos;    // current reading position
		int binplcs; // number of binary decimal places for read/write floating point

		streambuffer() : rpos(0), binplcs(16) {}

		template <typename T>
		void srlz(bool w, T& val);

		int remaining() { return static_cast<int>(size()) - rpos; }
	};

	template <>
	inline void streambuffer::srlz(bool w, uint8_t& val)
	{
		if (w) {
			push_back(val);
		} else {
			if (rpos + sizeof(val) > size()) return;
			val = this->operator[](rpos);
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, int8_t& val)
	{
		srlz(w, reinterpret_cast<uint8_t&>(val));
	}
	
	template <>
	inline void streambuffer::srlz(bool w, bool& val)
	{
		srlz(w, reinterpret_cast<uint8_t&>(val));
	}
	
	template <>
	inline void streambuffer::srlz(bool w, uint16_t& val)
	{
		if (w) {
			uint16_t vn = htons(val);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof val);
		} else {
			if (rpos + sizeof(val) > size()) return;
			val = ntohs(*reinterpret_cast<uint16_t*>(&this->operator[](rpos)));
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, int16_t& val)
	{
		srlz(w, reinterpret_cast<uint16_t&>(val));
	}
	
	template <>
	inline void streambuffer::srlz(bool w, uint32_t& val)
	{
		if (w) {
			uint32_t vn = htonl(val);
			uint8_t* p = reinterpret_cast<uint8_t*>(&vn);
			insert(end(), p, p + sizeof val);
		} else {
			if (rpos + sizeof(val) > size()) return;
			val = ntohl(*reinterpret_cast<uint32_t*>(&this->operator[](rpos)));
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, int32_t& val)
	{
		srlz(w, reinterpret_cast<uint32_t&>(val));
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
			if (rpos + sizeof(val) > size()) return;
			#ifdef __linux
			val = be64toh(*reinterpret_cast<uint64_t*>(&this->operator[](rpos)));
			#else
			val = ntohll (*reinterpret_cast<uint64_t*>(&this->operator[](rpos)));
			#endif
			rpos += sizeof val;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, int64_t& val)
	{
		srlz(w, reinterpret_cast<uint64_t&>(val));
	}
	
	template <>
	inline void streambuffer::srlz(bool w, float& val)
	{
		if (w) {
			int32_t ival = val * (1<<binplcs);
			srlz(w, ival);
		} else {
			int32_t ival = 0;
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
				// Invalid size!
				return;
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
				// Invalid size!
				return;
			}
		}
	}

	// Default fall-through for enum types
	template <typename T>
	inline void streambuffer::srlz(bool w, T& val)
	{
		len_t l(static_cast<typename std::underlying_type<T>::type>(val));
		srlz(w, l);
		val = static_cast<T>(l.v);
	}
	
	template <>
	inline void streambuffer::srlz(bool w, std::string& str)
	{
		if (w) {
			len_t l(str.size());
			srlz(w, l);
			insert(end(), str.begin(), str.end());
		} else {
			len_t l;
			srlz(w, l);
			
			// Size check for malicious data
			if (rpos + l.v > size()) return;
			
			uint8_t* p = &this->operator[](rpos);
			str = std::string(p, p + l.v);
			rpos += l.v;
		}
	}
	
	template <>
	inline void streambuffer::srlz(bool w, std::vector<uint8_t>& vec)
	{
		if (w) {
			len_t l(vec.size());
			srlz(w, l);
			insert(end(), vec.begin(), vec.end());
		} else {
			len_t l;
			srlz(w, l);

			// Size check for malicious data
			if (rpos + l.v > size()) return;
			
			uint8_t* p = &this->operator[](rpos);
			vec = std::vector<uint8_t>(p, p + l.v);
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
	
	struct receive_state {
		
		receive_state();
		
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
	
		enum state {
			UNKNOWN,
			INITIATING,
			INITIATED,
			VERSIONED,
			CONNECTED,
			DISCONNECTED
		};
		
		conn_info();
		~conn_info();

		char          addr_str[INET6_ADDRSTRLEN];
		receive_state r;
		tp            last_packet_recv;    // force timeout of client if they haven't responded
		tp            last_heartbeat_sent; // know when to send more heartbeats
		state         st;                  // state of the connection
		
		EVP_CIPHER_CTX* ctx_enc; // cipher context for encryption
		EVP_CIPHER_CTX* ctx_dec; // cipher context for decryption
		
		std::vector<uint8_t> session_key, iv; // session key and initialization vector
	};
	
	struct delayed_send {
		delayed_send();
		delayed_send(int fd, packet&& p, tp const& earliest);
		
		int    fd;
		packet p;
		tp     earliest;
	};
	
	class peer
	{
	public:

		peer();

		std::string address(int fd);
		ret_code    close(int fd);

		int fd;
		ms  lag_min, lag_max;

	protected:

		typedef std::unordered_map<int, conn_info> conn_map;

		bool cipher_init(
			bool encrypt,
			EVP_CIPHER_CTX* ctx,
			uint8_t const* key,
			uint8_t const* iv
		);
		
		bool cipher(
			EVP_CIPHER_CTX* ctx,
			std::vector<uint8_t> const& in,
			std::vector<uint8_t>& out
			);
		
		conn_map::iterator disconnect(conn_map::iterator conn_it);

		ret_code recv(int fd, conn_info& ci, packets& ps, int max = 0);
		ret_code send(int fd, conn_info& ci, packet&& p);

		void flush_backlog();
		bool poll_write();
		void remove_heartbeats(packets& ps);
		
		conn_map                   conns;   // all connections. server generally has multiple, client has one
		std::deque<delayed_send>   delayed; // packets that we intentionally want to send late
		std::default_random_engine rng;     // used to generate lag values
 		const EVP_CIPHER*          cphr;    // cipher used for encryption/decryption

	private:
	
		void     recv_packet(int fd, conn_info& ci, packets& ps);
		ret_code send_packet(int fd, conn_info& ci, packet& p);

		ret_code recv_sock(int fd, uint8_t* buffer, len_t bytes, len_t& recvd);
		ret_code send_sock(int fd, uint8_t const* data, size_t sz);
	};

	class server : public peer
	{
	public:
	
		server(
			uint16_t port,
			std::string const& pubkeyfile = std::string(),
			std::string const& prvkeyfile = std::string(),
			ms heartbeat_period = ms(4000),
			ms timeout = ms(30000),
			std::string const& logfile = std::string()
		);
		
		~server();
		
		void     disconnect(int cfd);
		packets  process(bool accept_new = true);
		ret_code send(int fd, packet&& p);
		size_t   num_conns();

	protected:

		EVP_PKEY* load_key(bool is_public, std::string const& filename);
		
		void      process_accept();
		ret_code  process_initiated(int cfd, conn_info& ci, packets& in, packets& out);
		ret_code  process_versioned(int cfd, conn_info& ci, packets& in, packets& out);
		
		ms        heartbeat_period;
		ms        timeout;
		
		EVP_PKEY* public_key;
		EVP_PKEY* private_key;
	};

	class client : public peer
	{
	public:
		
		client(std::string const& host, uint16_t port, ms timeout = ms(30000));
		
		void     disconnect();
		packets  process();
		ret_code send(packet&& p);

	protected:
	
		ret_code process_initiating();
		ret_code process_initiated(packets& in, packets& out);
		ret_code process_versioned(packets& in, packets& out);
		
		conn_info* ci;         // convenience pointer into peer connection map
		tp         conn_start;
		addrinfo*  res;
		ms         timeout;
	};
}
