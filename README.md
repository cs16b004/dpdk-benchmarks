# dpdk-benchmarks
A client-server code to bench-mark dpdk in different configurations
 - Use the config files to configure network machines for example:
	- In network.yml add all machines to use as either server or generator 
	```yaml
	- ampere00:  # machine/host name 
      id: 0 # id for machine
      mac: 1c:01:dd:51:b2:ae # mac address of the host
      ip: 192.168.2.115 # ipaddres for the host
      port: 8000 # port listened to by the machine
	```
    -  then in a host_{machine_name}.yml file specify
	```yaml
	host:
  		name: catskill #machine name
  		type: server # type server/generator
  		id: 4 # id in the network.yml file
  		target: [5] # target machine id from the network
	```

	- in dpdk.yml
	```yaml
	dpdk:
  		rx_threads: 5 # number of dpdk rx_threads in server and generator
  		tx_threads: 5 # number of dpdk tx_threads in generator 
  		pkt_size: 64 # size of each pkt 
  		pkt_burst_size: 64 # burst size for each snd and receive operation
  		rx_burst_size: 32 # void let it be for legacy purpose
  		report_interval: 1000 #report interval in milliseconds
  		option: ./server -a e3:00.0 -d librte_net_mlx5.so -d librte_mempool_ring.so -l 32-64 # dpdk eal parameters
		```
	- in cpu.yml
	```yaml
		cpu:
  			numa: 1 # numa socket to schedule threads on , prefer same socket asd NIC
  			core_per_numa: 32 # cores per NUMA socket
	```
	- to run 
	```shell
		sudo ./server -f config_files/cpu.yml -f config_files/dpdk.yml -f config_files/host_{machine_name}.yml -f config_files/network.yml -d 40
	```
	-d si duration inseconds.

	- sample output for hitting over 80Gbps on Connect X-5 NIC(100Gbps)
	```
	I [src/dpdk.cpp:172] 2023-09-15 06:12:08.894 | Total Packets sent: 11469376, Total received: 9781255, rate 11469376.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:09.894 | Total Packets sent: 11469376, Total received: 9788460, rate 11469376.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:10.894 | Total Packets sent: 11469376, Total received: 9789094, rate 11469376.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:11.895 | Total Packets sent: 11469504, Total received: 9781561, rate 11469504.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:12.895 | Total Packets sent: 11469696, Total received: 9786026, rate 11469696.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:13.895 | Total Packets sent: 11469312, Total received: 9786718, rate 11469312.000000
	I [src/dpdk.cpp:172] 2023-09-15 06:12:14.895 | Total Packets sent: 11469312, Total received: 9788830, rate 11469312.000000
	
	```
	- 11,469,312*1024*8/(1000*1000*1000) Gbps
	

