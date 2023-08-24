#include <signal.h>
#include "server_worker.hpp"

Server *server;

void signal_handler(int sig) {
    server->trigger_shutdown();
}

int main(int argc, char** argv) {
    Config::create_config(argc, argv);

    server = new Server;
    signal(SIGINT, signal_handler);
    server->start_worker();
    server->shutdown();
    //delete server;
    return 0;
}
