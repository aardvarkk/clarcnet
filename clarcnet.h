#pragma once

#include <arpa/inet.h>
#include <chrono>
#include <deque>
#include <fcntl.h>
#include <netdb.h>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <sys/poll.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace clarcnet {

	typedef int32_t ver_t;
	extern const ver_t ver_code;
	
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
	inline void streambuffer::srlz(bool w, int8_t& val)
	{
		srlz(w, reinterpret_cast<uint8_t&>(val));
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
			VERSIONING,
			VERSIONED,
			SECURING,
			SECURED,
			CONNECTED,
			DISCONNECTED
		};
		
		conn_info();

		char          addr_str[INET6_ADDRSTRLEN];
		receive_state r;
		tp            last_packet_recv;    // force timeout of client if they haven't responded
		tp            last_heartbeat_sent; // know when to send more heartbeats
		state         st;                  // state of the connection
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
		ret_code close(int fd);

		int fd;
		ms lag_min, lag_max;

	protected:

		void remove_heartbeats(packets& ps);
		bool poll_write();
		ret_code send_sock(int fd, void const* data, size_t sz);
		ret_code send_packet(int fd, packet &p);
		void flush_backlog();
		ret_code send(int fd, packet&& p);
		ret_code recv_into(int fd, void* buffer, len_t bytes, len_t& recvd);
		void finish_packet(int fd, conn_info &ci, packets &ps);
		ret_code receive(int fd, conn_info &ci, packets &ps);
		
		std::deque<delayed_send> delayed; // packets that we intentionally want to send late
		std::default_random_engine rng; // used to generate lag values
	};

	class server : public peer
	{
	public:
		server(uint16_t port, ms heartbeat_period = ms(4000), ms timeout = ms(15000));
		~server();
		ret_code send(int fd, packet&& p);
		packets process(bool accept_new = true);
		std::string address(int cfd);
		void disconnect(int cfd);

	protected:

		typedef std::unordered_map<int, conn_info> conn_map;
		conn_map::iterator disconnect(conn_map::iterator conn_it);
		conn_map conns;
		ms       heartbeat_period;
		ms       timeout;
	};

	class client : public peer
	{
	public:
		
		client(std::string const& host, uint16_t port, ms timeout = ms(0));
		void disconnect();
		ret_code send(packet&& p);
		packets process();
		std::string address();

	protected:
		tp        conn_start;
		conn_info ci;
		addrinfo* res;
		ms        timeout;
	};
}
