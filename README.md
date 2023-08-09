# dpdk-benchmarks
A client-server code to bench-mark dpdk in different configurations
$(CC) $^ $(CFLAGS) -o $@ $(LIBS)
@mkdir -p $(@D)
	echo $(CFLAGS)
	$(CC) -c -o $@ $< $(CFLAGS)
