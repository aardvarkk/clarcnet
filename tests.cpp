#include "clarcnet.h"

#include <thread>

using namespace clarcnet;
using namespace std;

server* sv;
client* cl;
mutex   m;

#define LOG_S lock_guard<mutex> lk(m);

const size_t _max_packet = UINT8_MAX + UINT16_MAX;

int main(int argc, char* argv[]) {
	thread t_s([](){
		sv = new server(5000);
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
		cl = new client("localhost", 5000);

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
				cl->send(std::move(p));
			}
		}
	});

	t_s.join();
	t_c.join();
}