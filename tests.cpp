#include "clarcnet.h"

#include <thread>

using namespace clarcnet;
using namespace std;

server* sv;
client* cl;
mutex   m;

#define LOG_S lock_guard<mutex> lk(m);

const int _max_packet = 50;

int main(int argc, char* argv[]) {
	thread t_s([](){
		sv = new server(5000);
		for (;;) {
			auto ps = sv->process();

			for (auto const& p : ps) {
				switch (p.mid) {
					case ID_CONNECTION:
					{
						LOG_S;
						cout << "connection from client" << endl;
					}
					break;

					case ID_DISCONNECTION:
					{
						LOG_S;
						cout << "disconnection from client" << endl;
					}
					break;

					case ID_USER:
					{
						LOG_S;
						for (auto i = 0; i < p.size(); ++i) {
							cout << p[i];
						}
						cout << endl;
					}
				}
			}
		}
	});

	thread t_c([](){
		cl = new client("localhost", 5000);

		bool connected = false;

		for (;;) {
			auto ps = cl->process();

			for (auto const& p : ps) {
				switch (p.mid) {
					case ID_CONNECTION:
					{
						LOG_S;
						cout << "connected to server" << endl;
						connected = true;
					}
					break;

					case ID_DISCONNECTION:
					{
						LOG_S;
						cout << "disconnected from server" << endl;
						connected = false;
					}
					break;
				}
			}

			if (connected) {
				size_t els = rand() % _max_packet;
				packet p(ID_USER);
				p.resize(els);
				for (auto i = 0; i < els; ++i) p[i] = '0' + i % 10;

				LOG_S
				cout << "sending " << p.size() << endl;
				cl->send(p);

				connected = !connected;
			}
		}
	});

	t_s.join();
	t_c.join();
}