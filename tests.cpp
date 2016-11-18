#include "clarcnet.h"

#include <iostream>
#include <thread>

using namespace clarcnet;
using namespace std;

server* sv;
client* cl;
mutex   m;

#define LOG_S lock_guard<mutex> lk(m);

const int _port = 5000;
const size_t _max_packet = UINT8_MAX + UINT16_MAX;

void test_bidirectional() 
{
	thread t_s([](){
		sv = new server(_port);
		for (;;) {
			auto ps = sv->process();

			for (auto const& p : ps) {
				LOG_S;
				cout << "Server received " << msg_strs[p.mid] << endl;

				if (p.mid == ID_USER) {
					for (auto i = 0; i < p.size(); ++i) {
						cout << p[i];
					}
					cout << endl;
				}
			}
		}
	});

	thread t_c([](){
		cl = new client("localhost", _port);

		bool connected = false;

		default_random_engine rng;
		rng.seed(5);

		for (;;) {
			auto ps = cl->process();

			for (auto const& p : ps) {
				LOG_S;
				cout << "Client received " << clarcnet::msg_strs[p.mid] << endl;

				if (p.mid == ID_CONNECTION) connected = true;
			}

			if (connected) {
				packet p(ID_USER);
				size_t els = rng() % _max_packet;
				p.resize(els);
				for (auto i = 0; i < els; ++i) p[i] = '0' + i % 10;
				cl->send(move(p));

				this_thread::sleep_for(chrono::seconds(1));
			}
		}
	});

	t_s.join();
	t_c.join();
}

// We were getting segfaults if the client sent an ID_USER message ID or higher
// because we'd try to decrypt it before the decryption was actually setup
// We try sending packets to the server without waiting for connection to occur
// The server should forcefully disconnect us for being a bad client
void test_early_user_send()
{
	thread t_s([](){
		sv = new server(_port);
		for (;;) {
			auto ps = sv->process();
			for (auto const& p : ps) {
				LOG_S;
				cout << "Server received " << clarcnet::msg_strs[p.mid] << endl;
			}
		}
	});

	thread t_c([](){
		cl = new client("localhost", _port);
		for (;;) {
			auto ps = cl->process();
			for (auto const& p : ps) {
				LOG_S;
				cout << "Client received " << clarcnet::msg_strs[p.mid] << endl;
			}
			packet p(ID_USER);
			cl->send(move(p));
		}
	});

	t_s.join();
}

int main(int argc, char* argv[])
{
	test_early_user_send();
	return EXIT_SUCCESS;
}