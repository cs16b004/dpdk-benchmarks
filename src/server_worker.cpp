#include <chrono>
#include <fstream>
#include "../deps.hpp"
#include "config.hpp"
#include "server_worker.hpp"

Server::Server() {
    config = Config::get_config();
    dpdk_.init(config);

    /* auto* dpdk_workload = Workload::create_workload(-1, config); */
    /* assert(dpdk_workload != nullptr); */
    /* workload_set.push_back(dpdk_workload); */
  
}

void Server::start_worker() {
   
}

void Server::run_open_client(int client_id) {
   
}

void Server::check_server_id() {
    //current_server = config->get_default_server();

   
}

void Server::shutdown() {
   sleep(Config::get_config()->duration);
   trigger_shutdown();
}

void Server::trigger_shutdown() {
    force_quit = true;
    dpdk_.trigger_shutdown();
}

