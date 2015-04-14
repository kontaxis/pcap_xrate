.PHONY: all debug clean

all: xrate xrate_noether

debug: xrate_dbg xrate_noether_dbg

xrate: pcap_xrate.c
	gcc -Wall \
		pcap_xrate.c \
		-o xrate \
		-lpcap

xrate_dbg: pcap_xrate.c
	gcc -Wall -ggdb -O0 -D__DEBUG__ \
		pcap_xrate.c \
		-o xrate_dbg \
		-lpcap

xrate_noether: pcap_xrate.c
	gcc -Wall \
		-D__NO_ETHERNET__ \
		pcap_xrate.c \
		-o xrate_noether \
		-lpcap

xrate_noether_dbg: pcap_xrate.c
	gcc -Wall -ggdb -O0 -D__DEBUG__ \
		-D__NO_ETHERNET__ \
		pcap_xrate.c \
		-o xrate_noether_dbg \
		-lpcap

clean:
	rm -f xrate xrate_dbg xrate_noether xrate_noether_dbg

