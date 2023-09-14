#ifndef _DPDK_H_
#define _DPDK_H_

#include <cstdint>
#include "config.hpp"
/* #include "workload.h" */

class Dpdk {
private:
    struct NetAddress;
    struct packet_stats;
    struct dpdk_thread_info;
   
    uint8_t* data_arr;
private:
    int port_num_ = 0;
    int tx_threads_ = 0;
    int rx_threads_ = 0;
    uint16_t rx_queue_ = 1, tx_queue_ = 1;
    struct rte_mempool **tx_mbuf_pool;
    struct rte_mempool **rx_mbuf_pool;
    struct dpdk_thread_info **thread_rx_info{nullptr};
    struct dpdk_thread_info **thread_tx_info{nullptr};
    struct dpdk_thread_info *thread_stat_info; 
    std::function<int(uint8_t*, int, int, int)> response_handler;
    std::thread main_thread;
    bool force_quit{false};
    std::vector<NetAddress> addr_vec_;
    Config* config_;

private:
    void addr_config(std::vector<Config::NetworkInfo> net_info);
    void init_dpdk_main_thread(const char* argv_str);
    void init_dpdk_echo(const char* argv_str);
    
    int port_init(uint16_t port_id);
    int port_reset(uint16_t port_id);
    int port_close(uint16_t port_id);
    void install_flow_rule(size_t phy_port);
    static int dpdk_rx_loop(void* arg);
    static int dpdk_tx_loop(void* arg);
    static int dpdk_stat_loop(void*arg);

    void process_incoming_packets(dpdk_thread_info* rx_buf_info);

    int make_pkt_header(uint8_t *pkt, int payload_len,
                        int src_id, int dest_id, int port_offset);
    NetAddress get_net_from_id(uint16_t id_){
        for(auto ni:addr_vec_){

            if(ni.id == id_){
               // log_debug("Found net info with ID %d",id_);
                return ni;
            }
        }
        return addr_vec_[0];
    }                    


public:
    void init(Config* config);

    void shutdown();
    void trigger_shutdown();
    
    void register_resp_callback();

    ~Dpdk() {
        if (thread_rx_info)
            delete[] thread_rx_info;
        if (thread_tx_info)
            delete[] thread_tx_info;
        if (tx_mbuf_pool)
            delete[] tx_mbuf_pool;
        if (rx_mbuf_pool)
            delete[] rx_mbuf_pool;
    }

private:
    struct NetAddress {
        uint8_t id;

        uint8_t mac[6];
        uint32_t ip;
        uint16_t port;

        NetAddress() {};
        NetAddress(const char* mac_i, const char* ip_i, const int port);
        NetAddress(const uint8_t* mac_i, const uint32_t ip, const int port);
        void init(const char* mac_i, const char* ip_i, const int port);
        bool operator==(const NetAddress& other);
        NetAddress& operator=(const NetAddress& other);
    };
    struct dpdk_thread_info {
        uint16_t thread_id_; /* Thread ID from 0 to num_rx_threads_ - 1  or num_tx_threads_ -1 */
        uint8_t port_id_; /*ETHER port ID  0 to num_ports_ -1 */
        uint16_t queue_id_; /*Ether Queue ID (Better Parallelism)  each rx/tx thread has its own queue so same as thread_id */
        uint64_t rcv_count_ = 0; /*Packet received each thread will count and merge will happen at time of reporting to avoid locking*/
        uint64_t id_counter_; 
        
        uint64_t snd_count_=0;
        
        int udp_port = 0; /*UDP port num form config*/
        struct rte_mbuf **buf{nullptr}; /* mbufs array*/
        Dpdk* dpdk_th; 

        dpdk_thread_info() { }
        void init(Dpdk* th, uint16_t th_id, uint8_t p_id,
                  uint16_t q_id, uint64_t id_conter);
        int buf_alloc(struct rte_mempool* mbuf_pool);
        void make_headers();
        void make_pkt_header(struct rte_mbuf* pkt);
        ~dpdk_thread_info() {
            if (buf)
                delete [] buf;
        }
    };

    
};

#endif
