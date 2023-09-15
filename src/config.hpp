#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <string>
#include <cstdint>
#include "../deps.hpp"
#include <yaml-cpp/yaml.h>

class Config {
private:

public:

    struct NetworkInfo {
        std::string name;
        int id;
        std::string mac;
        std::string ip;
        uint32_t port;
        std::string to_string(){
            std::stringstream ss;
            ss<<"[ Name: "<<name<<"\n  Id : "<<id<<"\n  MAC: "<<mac<<"\n  IP: "<<ip<<"\n  Port : "<<port<<"\n";
            return ss.str();
        }
    };

    /* TODO: use system info instead of file for boundries; Specially when
     * there is more than one NUMA core */
    struct CpuInfo {
        int numa;
        int core_per_numa;
        int max_rx_threads;
        int max_tx_threads;
    };

private:
    std::vector<std::string> config_paths_;
   
public:
    static Config* config_s;
    uint64_t duration = 100; //duration in seconds;
    uint16_t burst_size;
    uint16_t rx_burst_size;
    uint16_t pkt_len;
    std::string host_name_;
    std::string name_;
    std::vector<NetworkInfo> net_info_;
    std::string dpdk_options_;
    std::vector<uint16_t> target_ids_;
    uint16_t src_id_;
    uint16_t report_interval_ = 5000;
    CpuInfo cpu_info_;

    
    uint16_t num_tx_threads_;
    uint16_t num_rx_threads_;
    enum{ GENERATOR, SERVER} host_type_;

private:

    void load_cfg_files();
    void load_yml(std::string& filename);
    void load_network_yml(YAML::Node config);
    void load_dpdk_yml(YAML::Node config);
    void load_cpu_yml(YAML::Node config);
    void load_host_yml(YAML::Node config);
 
   // void load_partition_type(YAML::Node config);

public:
    static int create_config(int argc, char** argv);
    static Config* get_config();

    const char* get_dpdk_options() const {
        return dpdk_options_.c_str();
    }
    Config::CpuInfo get_cpu_info() const {
        return cpu_info_;
    }
    std::vector<Config::NetworkInfo> get_net_info() const {
        return net_info_;
    }

    
   
    
};
#endif