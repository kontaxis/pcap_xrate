# This program takes an offline pcap trace and counts the total size of IPv4
# packets. (header + data) Outputs the time difference between the first and
# last packet. Used to calculate transmission rate in lack of other methods.
#
# Note: To calculate Tx or Rx rate the pcap trace must contain only Tx or Rx
#       packets respectively. Otherwise the transmission rate calculated will
#       be the aggregate of both directions.
#
# kontaxis 2015-04-14

# Build
make

# Clean
make clean

# Collect an offline pcap trace every 60 seconds, 5 times
tcpdump -n -i eth0 -G 60 -W 5 -w mycap-%s \
	ip and host 127.0.0.1 and tcp and not port 22

# Calculate xrate
./xrate `ls -t mycap-* | head -n 1`

