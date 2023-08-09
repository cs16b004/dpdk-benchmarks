#ifndef _SERVER_WORKER_H_
#define _SERVER_WORKER_H_

#include "dpdk.hpp"
/* #include "workload.h" */

class Server {
private:
    Config* config = nullptr;
    Dpdk dpdk_;
    bool force_quit{false};
    std::vector<std::thread> client_workers;
    /* std::vector<Workload*> workload_set; */

    std::thread server_check_thread;
    int current_server = 0;

private:
    void run_open_client(int client_id);
    void check_server_id();

public:
    Server();
    void start_worker();
    void shutdown();
    void trigger_shutdown();
    ~Server() {
        /* for (auto& workload: workload_set) */
            /* delete workload; */
    }
};

#endif
