
#include <cstdint>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_pmd_qdma.h>
#include <string>
#include <sstream>
#include<iomanip>
#include<iostream>
#include "dpdkdef.hpp"
#include "dpdk.hpp"
#include <sched.h>

#include <unistd.h>
#include <stdlib.h>

#define DPDK_RX_DESC_SIZE           1024
#define DPDK_TX_DESC_SIZE           1024

#define DPDK_NUM_MBUFS              8192
#define DPDK_MBUF_CACHE_SIZE        250
#define DPDK_RX_BURST_SIZE          64
#define DPDK_TX_BURST_SIZE          1

#define DPDK_RX_WRITEBACK_THRESH    64

#define DPDK_PREFETCH_NUM           2

#define DPDK_COUNTER_DIFF 3*1000*1000

const uint16_t DATA_OFFSET = sizeof(struct rte_ether_hdr) + sizeof(struct ipv4_hdr_t) + sizeof(struct udp_hdr_t);
const uint16_t IPV4_OFFSET =  sizeof(struct rte_ether_hdr);
const uint16_t UDP_OFFSET = sizeof(struct rte_ether_hdr) + sizeof(struct ipv4_hdr_t);

static void inline swap_udp_addresses(struct rte_mbuf *pkt) {
    // Extract Ethernet header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    // Extract IP header
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    // Extract UDP header
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);

    // Swap IP addresses
    uint32_t tmp_ip = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = tmp_ip;

    // Swap UDP port numbers
    uint16_t tmp_port = udp_hdr->src_port;
    udp_hdr->src_port = udp_hdr->dst_port;
    udp_hdr->dst_port = tmp_port;
}

int Dpdk::dpdk_rx_loop(void* arg) {
   dpdk_thread_info* info = (dpdk_thread_info*) arg ;
   uint16_t num_rx=0,num_tx=0;
    Config* conf = Config::get_config();
   const uint16_t burst_size = conf->burst_size;
   log_info("Launching rx thread %d, on lcore: %d, id counter %d on cpu %d",info->thread_id_, rte_lcore_id(),info->id_counter_,sched_getcpu());
    while(!info->dpdk_th->force_quit){
        ;
        num_rx  = rte_eth_rx_burst(info->port_id_, info->queue_id_, info->buf,burst_size);
        info->rcv_count_+=num_rx;
        // Send the packets back if server;
        // calculate latency if generator;
        if(conf->host_type_ == Config::SERVER){
            for(int i=0;i<num_rx;i++)
                swap_udp_addresses(info->buf[i]);
            num_tx = rte_eth_tx_burst(info->port_id_,info->queue_id_,info->buf,num_rx);
            info->snd_count_+=num_tx;
        }

    }
   return 0;

}
int Dpdk::dpdk_stat_loop(void *arg){
    dpdk_thread_info* info = (dpdk_thread_info*) arg ;
    log_info("Launching stat thread %d, on lcore: %d, on cpu %d",info->thread_id_, rte_lcore_id(), sched_getcpu());

    uint64_t total_rcv_count=0;
    uint64_t total_snd_count=0;
    uint64_t last_total_rcv=0;
    uint64_t last_total_snd=0;
    
     Config* conf = Config::get_config();
     uint64_t last_rcv_count[conf->num_rx_threads_] = {0};
     uint64_t last_snd_count[conf->num_tx_threads_] = {0};
    std::stringstream tab;
    
    while(!info->dpdk_th->force_quit){
        usleep(conf->report_interval_ * 1000);// sleep for report interval seconds;
        //Print the stat table
        tab << std::left << std::setw(20) << "Thread ID"
              << std::setw(20) << "num_rcv_pkts"
              << std::setw(20) << "num_snd_pkts" << std::endl;
        tab << std::setfill('-') << std::setw(70) << "" << std::endl;

        for(int i=0;i<info->dpdk_th->rx_threads_;i++){
            std::string thread_id = "rx-" + std::to_string(i);

            tab << std::setfill(' ') << std::left << std::setw(20) << thread_id
              << std::setw(20) << info->dpdk_th->thread_rx_info[i]->rcv_count_ - last_rcv_count[i]
              << std::setw(20) << info->dpdk_th->thread_rx_info[i]->snd_count_ << std::endl;
            
            last_rcv_count[i] = info->dpdk_th->thread_rx_info[i]->rcv_count_;
            
            total_rcv_count += info->dpdk_th->thread_rx_info[i]->rcv_count_;
              
        }
        total_rcv_count -= last_total_rcv;
        last_total_rcv = total_rcv_count;
        ;

        for(int i=0;i<info->dpdk_th->tx_threads_;i++){
            std::string thread_id = "tx-" + std::to_string(i);

            tab << std::setfill(' ') << std::left << std::setw(20) << thread_id
              << std::setw(20) << 0
              << std::setw(20) << info->dpdk_th->thread_tx_info[i]->snd_count_ - last_snd_count[i] << std::endl;
            
            last_snd_count[i] = info->dpdk_th->thread_tx_info[i]->snd_count_ ;
            total_snd_count += info->dpdk_th->thread_tx_info[i]->snd_count_;
              
        }
        total_snd_count -= last_total_snd;
        last_total_snd = total_snd_count;
        log_info("\n %s\n Total Packets sent: %lld, Total received: %lld",tab.str().c_str(), total_rcv_count, total_snd_count);
        tab.clear();
    }
    return 0;
}      
int Dpdk::dpdk_tx_loop(void* arg) {
   dpdk_thread_info* info = (dpdk_thread_info*) arg ;
   
   uint16_t burst_size = Config::get_config()->burst_size;
   

   info->make_headers();
    
   Config* conf = Config::get_config();
   int ret;
    log_info("Launching tx thread %d, on lcore: %d, id counter %d, burst_size %d, on cpu %d",info->thread_id_, rte_lcore_id(),info->id_counter_,burst_size, sched_getcpu());
    while(!info->dpdk_th->force_quit){
        
        rte_prefetch0(info->buf);
        for(int i=0;i<burst_size;i++){


            rte_ether_hdr* eth_hdr = reinterpret_cast<rte_ether_hdr*>(info->buf[i]);
            
            log_debug("Packet id %lld is mac: %s",info->id_counter_,mac_to_string((eth_hdr->d_addr).addr_bytes).c_str());
            uint8_t* pkt_arr = rte_pktmbuf_mtod(info->buf[i], uint8_t*);
            rte_memcpy(pkt_arr + DATA_OFFSET, &(info->id_counter_), sizeof(uint64_t));
            info->id_counter_++;
        }
        log_debug("PKt Address while sending %p",&(info->buf[0]));
        ret = rte_eth_tx_burst(info->port_id_,info->queue_id_,info->buf,conf->burst_size);
        if (unlikely(ret <= 0))
            log_error("Tx couldn't send\n");   
       
        info->snd_count_+=ret;

        rte_prefetch0(info->buf);
        //break;
    }
    log_info("Thread %d sent %d pkts", info->thread_id_ ,info->snd_count_);
   return 0;

}


void Dpdk::init(Config* config) {
    
    config_ = config;
    
    addr_config(config->get_net_info());

    Config::CpuInfo cpu_info = config->get_cpu_info();
    const char* argv_str = config->get_dpdk_options();
    tx_threads_ = config->num_rx_threads_;
    rx_threads_ = config->num_tx_threads_;
   
    data_arr = new uint8_t[config->pkt_len];
    for(int i=0;i<config->pkt_len;i++){
        data_arr[i] = 0x0;
    }
    main_thread = std::thread([this, argv_str](){
        this->init_dpdk_main_thread(argv_str);
    });
    sleep(2);
}

void Dpdk::init_dpdk_main_thread(const char* argv_str) {
    std::vector<const char*> dpdk_argv;
    char* tmp_arg = const_cast<char*>(argv_str);
    const char* arg_tok = strtok(tmp_arg, " ");
    while (arg_tok != NULL) {
        dpdk_argv.push_back(arg_tok);
        arg_tok = strtok(NULL, " ");
    }
    int argc = dpdk_argv.size();
    char** argv = const_cast<char**>(dpdk_argv.data());

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    port_num_ = rte_eth_dev_count_avail();
    if (port_num_ < 1)
        rte_exit(EXIT_FAILURE, "Error with insufficient number of ports\n");

    tx_queue_ = tx_threads_ ;
    rx_queue_ = rx_threads_ ;
    tx_mbuf_pool = new struct rte_mempool*[tx_threads_];
    for (int pool_idx = 0; pool_idx < tx_threads_; pool_idx++) {
        char pool_name[1024];
        sprintf(pool_name, "TX_MBUF_POOL_%d", pool_idx);
        /* TODO: Fix it for machines with more than one NUMA node */
        tx_mbuf_pool[pool_idx] = rte_pktmbuf_pool_create(pool_name, DPDK_NUM_MBUFS,
                                                         DPDK_MBUF_CACHE_SIZE, 0, 
                                                         RTE_MBUF_DEFAULT_BUF_SIZE, 
                                                         rte_socket_id());
        if (tx_mbuf_pool[pool_idx] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create tx mbuf pool %d\n", pool_idx);
    }

    rx_mbuf_pool = new struct rte_mempool*[rx_threads_];
    for (int pool_idx = 0; pool_idx < rx_threads_; pool_idx++) {
        char pool_name[1024];
        sprintf(pool_name, "RX_MBUF_POOL_%d", pool_idx);
        /* TODO: Fix it for machines with more than one NUMA node */
        rx_mbuf_pool[pool_idx] = rte_pktmbuf_pool_create(pool_name, DPDK_NUM_MBUFS,
                                                         DPDK_MBUF_CACHE_SIZE, 0, 
                                                         RTE_MBUF_DEFAULT_BUF_SIZE, 
                                                         rte_socket_id());
        if (rx_mbuf_pool[pool_idx] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create rx mbuf pool %d\n", pool_idx);
    }

    /* Will initialize buffers in port_init function */
    this->thread_rx_info = new dpdk_thread_info*[rx_threads_];
    this->thread_tx_info = new dpdk_thread_info*[tx_threads_];
    this->thread_stat_info = new dpdk_thread_info;

    uint16_t portid;
    RTE_ETH_FOREACH_DEV(portid) {
       
        if (port_init(portid) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                     portid);
    }

    log_info("DPDK tx threads %d, rx threads %d", tx_threads_, rx_threads_);

    uint16_t total_lcores = rte_lcore_count();
 
    log_info("Total Cores available: %d",total_lcores);
    uint16_t rx_lcore_lim = (config_->host_type_ == Config::GENERATOR)? (rx_threads_+tx_threads_)/2: rx_threads_;
    uint16_t tx_lcore_lim = (config_->host_type_ == Config::GENERATOR) ? rx_threads_ + tx_threads_: 0;

    uint8_t numa_id =  rte_eth_dev_socket_id(port_num_-1);
    // Add core per numa so that threads are scheduled on rigt lcores
    uint16_t lcore;
    rx_lcore_lim += numa_id * Config::get_config()->cpu_info_.core_per_numa;
    tx_lcore_lim += numa_id * Config::get_config()->cpu_info_.core_per_numa;
    log_info("rx_core limit: %d tx_core limit: %d",rx_lcore_lim,tx_lcore_lim);
    for (lcore = numa_id * Config::get_config()->cpu_info_.core_per_numa + 1; lcore < rx_lcore_lim+1; lcore++) {
            
            int retval = rte_eal_remote_launch(dpdk_rx_loop, this->thread_rx_info[lcore%rx_threads_], lcore );
            if (retval < 0)
                rte_exit(EXIT_FAILURE, "Couldn't launch core %d\n", lcore % total_lcores);
       
        
    }

    
    for (lcore = rx_lcore_lim+1; lcore < tx_lcore_lim+1; lcore++) {
            
            int retval = rte_eal_remote_launch(dpdk_tx_loop, this->thread_tx_info[lcore%tx_threads_], lcore );
            if (retval < 0)
                rte_exit(EXIT_FAILURE, "Couldn't launch core %d\n", lcore % total_lcores);
        
    }
    // Launch stat thread
    int retval = rte_eal_remote_launch(dpdk_stat_loop, this->thread_stat_info, lcore);
            if (retval < 0)
                rte_exit(EXIT_FAILURE, "Couldn't launch core %d\n", lcore % total_lcores);
    
}

void Dpdk::addr_config(std::vector<Config::NetworkInfo> net_info) {
    for (auto& net : net_info) {
        NetAddress n_addr = NetAddress(net.mac.c_str(),net.ip.c_str(),net.port);
        n_addr.id = net.id;
        addr_vec_.push_back(n_addr);
    
    }
}

int Dpdk::port_init(uint16_t port_id) {
    struct rte_eth_conf port_conf;
    uint16_t nb_rxd = DPDK_RX_DESC_SIZE;
    uint16_t nb_txd = DPDK_TX_DESC_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    struct rte_eth_rxconf rxconf;
    struct rte_device *dev;

    dev = rte_eth_devices[port_id].device;
    if (dev == nullptr) {
        log_error("Port %d is already removed", port_id);
        return -1;
    }

    if (!rte_eth_dev_is_valid_port(port_id))
        return -1;

    retval = rte_eth_dev_info_get(port_id, &dev_info);
    if (retval != 0) {
        log_error("Error during getting device (port %u) info: %s",
                  port_id, strerror(-retval));
        return retval;
    }

    memset(&port_conf, 0x0, sizeof(struct rte_eth_conf));
    memset(&txconf, 0x0, sizeof(struct rte_eth_txconf));
    memset(&rxconf, 0x0, sizeof(struct rte_eth_rxconf));


     port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
		},
	};
    
    port_conf.txmode.offloads &= dev_info.tx_offload_capa;

    rxconf = dev_info.default_rxconf;
	rxconf.offloads = port_conf.rxmode.offloads;
   


    retval = rte_eth_dev_configure(port_id, rx_queue_, tx_queue_, &port_conf);
    if (retval != 0) {
        log_error("Error during device configuration (port %u) info: %s",
                  port_id, strerror(-retval));
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0) {
        log_error("Error during setting number of rx/tx descriptor (port %u) info: %s",
                  port_id, strerror(-retval));
        return retval;
    }

    rxconf.rx_thresh.wthresh = DPDK_RX_WRITEBACK_THRESH;
    for (q = 0; q < rx_queue_; q++) {
        int pool_idx =  q;
        retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                        rte_eth_dev_socket_id(port_id),
                                        &rxconf, rx_mbuf_pool[pool_idx]);
        if (retval < 0) {
            log_error("Error during rx queue %d setup (port %u) info: %s",
                      q, port_id, strerror(-retval));
            return retval;
        }
    }

    for (q = 0; q < tx_queue_; q++) {

        retval = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                        rte_eth_dev_socket_id(port_id),
                                        &txconf);
        if (retval < 0) {
            log_error("Error during tx queue %d setup (port %u) info: %s",
                      q, port_id, strerror(-retval));
            return retval;
        }
    }

    retval = rte_eth_dev_start(port_id);
    if (retval < 0) {
        log_error("Error during starting device (port %u) info: %s",
                  port_id, strerror(-retval));
        return retval;
    }

    for (int i = 0; i < rx_threads_; i++) {
       thread_rx_info[i] = new dpdk_thread_info();
        log_debug("Create rx thread %d info on port %d and queue %d",i, port_id, i);
       thread_rx_info[i]->init(this, i, port_id, i, 0);
       thread_rx_info[i]->buf_alloc(rx_mbuf_pool[i]);
    }

    for (int i = 0; i < tx_threads_; i++) {
        thread_tx_info[i] = new dpdk_thread_info();
        log_debug("Create tx thread %d info on port %d and queue %d, id_counter: %d",i, port_id, i,i*DPDK_COUNTER_DIFF);
        thread_tx_info[i]->init(this, i, port_id, i, i*DPDK_COUNTER_DIFF);
        thread_tx_info[i]->buf_alloc(tx_mbuf_pool[i]);
    }
    thread_stat_info->init(this,0,port_id,0,0);
    return 0;
}

int Dpdk::port_close(uint16_t port_id) {
    rte_eth_dev_stop(port_id);
    return 0;
}

int Dpdk::port_reset(uint16_t port_id) {
    struct rte_device* dev = rte_eth_devices[port_id].device;
    if (dev == nullptr) {
        log_error("Port %d is already removed", port_id);
        return -1;
    }

    int retval = port_close(port_id);
    if (retval < 0) {
        log_error("Error: Failed to close device for port: %d", port_id);
        return retval;
    }

    retval = rte_eth_dev_reset(port_id);
    if (retval < 0) {
        log_error("Error: Failed to reset device for port: %d", port_id);
        return -1;
    }

    retval = port_init(port_id);
    if (retval < 0) {
        log_error("Error: Failed to initialize device for port %d", port_id);
        return -1;
    }

    return 0;
}

void Dpdk::shutdown() {
    main_thread.join();
    rte_eal_mp_wait_lcore();

    for (int port_id = 0; port_id < port_num_; port_id++) {
        struct rte_device *dev = rte_eth_devices[port_id].device;
        if (dev == nullptr) {
            log_error("Port %d is already removed", port_id);
            continue;
        }

        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
        int ret = rte_dev_remove(dev);
        if (ret < 0)
            log_error("Failed to remove device on port: %d", port_id);

    }

    rte_eal_cleanup();
}

void Dpdk::trigger_shutdown() {
    force_quit = true;
}

void Dpdk::register_resp_callback() {
    response_handler = [&](uint8_t* data, int data_len,
                          int server_id, int client_id) -> int {
        log_debug("client %d got xid %ld", client_id, *reinterpret_cast<uint64_t*>(data));

        return data_len;
    };
}

/* void Dpdk::register_resp_callback(Workload* app) { */
/*     response_handler = [app](uint8_t* data, int data_len, int id) -> int { */
/*         return app->process_workload(data, data_len, id); */
/*     }; */
/* } */


int Dpdk::dpdk_thread_info::buf_alloc(struct rte_mempool* mbuf_pool) {
    
    int retval = rte_pktmbuf_alloc_bulk(mbuf_pool, buf, Config::get_config()->burst_size);
    return retval;
}

void Dpdk::dpdk_thread_info::make_headers(){
    for(int i=0;i<Config::get_config()->burst_size;i++){
        log_debug("Packet address for pkt %d while making header: %p",i,&buf[i]);
        make_pkt_header(buf[i]);
    }
}

void Dpdk::dpdk_thread_info::make_pkt_header(struct rte_mbuf* pkt){
    Config* conf = Config::get_config();
    uint16_t pkt_offset=0;
   
     pkt->data_len = conf->pkt_len;
    pkt->next = NULL;
    pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    /* Initialize Ethernet header. */
     uint8_t* pkt_buf = rte_pktmbuf_mtod(pkt, uint8_t*);

    NetAddress src_addr = dpdk_th->get_net_from_id(conf->src_id_);
    NetAddress dest_addr = dpdk_th->get_net_from_id(conf->target_ids_[0]);
   
    rte_ether_hdr* eth_hdr = reinterpret_cast<rte_ether_hdr*>(pkt_buf);
    gen_eth_header(eth_hdr, src_addr.mac, dest_addr.mac);

    log_debug("Making pkt ether addr %s at address %p",mac_to_string(eth_hdr->d_addr.addr_bytes).c_str(), eth_hdr);

    pkt_offset += sizeof(rte_ether_hdr);
    rte_ipv4_hdr* ipv4_hdr = reinterpret_cast<rte_ipv4_hdr*>(pkt_buf + pkt_offset);
    gen_ipv4_header(ipv4_hdr, src_addr.ip, (dest_addr.ip),conf->pkt_len);

    pkt_offset += sizeof(ipv4_hdr_t);
    rte_udp_hdr* udp_hdr = reinterpret_cast<rte_udp_hdr*>(pkt_buf + pkt_offset);
   
    gen_udp_header(udp_hdr, src_addr.port, dest_addr.port , conf->pkt_len);

    pkt_offset += sizeof(udp_hdr_t);
    pkt->pkt_len = conf->pkt_len;
    pkt->l2_len = sizeof(struct rte_ether_hdr);
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    pkt->l4_len = sizeof(struct rte_udp_hdr);
    pkt->nb_segs = 1;
    rte_memcpy(pkt_buf + pkt_offset, dpdk_th->data_arr, conf->pkt_len);

}

void Dpdk::NetAddress::init(const char* mac_i, const char* ip_i, const int port_i) {
    mac_from_str(mac_i, mac);
    ip = ipv4_from_str(ip_i);
    port = port_i;
}

Dpdk::NetAddress::NetAddress(const char* mac_i, const char* ip_i, const int port_i) {
    init(mac_i, ip_i, port_i);
}

Dpdk::NetAddress::NetAddress(const uint8_t* mac_i, const uint32_t ip_i, const int port_i) {
    memcpy(mac, mac_i, sizeof(mac));
    ip = ip_i;
    port = port_i;
}

bool Dpdk::NetAddress::operator==(const NetAddress& other) {
    if (&other == this)
        return true;

    for (uint8_t i = 0; i < sizeof(mac); i++)
        if (this->mac[i] != other.mac[i])
            return false;

    if ((this->ip != other.ip) || (this->port != other.port))
        return false;

    return true;
}

Dpdk::NetAddress& Dpdk::NetAddress::operator=(const NetAddress& other) {
    if (this == &other)
        return *this;

    memcpy(this->mac, other.mac, sizeof(this->mac));
    this->ip = other.ip;
    this->port = other.port;

    return *this;
}
void Dpdk::dpdk_thread_info::init(Dpdk* th, uint16_t th_id, uint8_t p_id,
                  uint16_t q_id, uint64_t id_counter){
                    this->dpdk_th = th;
                    this->thread_id_ = th_id;
                    this->port_id_ = p_id;
                    this->queue_id_ =q_id;
                    this->id_counter_ = id_counter;
                    buf = new struct rte_mbuf*[Config::get_config()->burst_size];

                  }