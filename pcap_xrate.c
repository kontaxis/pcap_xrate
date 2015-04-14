/* This program takes an offline pcap trace and counts the total size of IPv4
 * packets. (header + data) Outputs the time difference between the first and
 * last packet. Used to calculate transmission rate in lack of other methods.
 *
 * Note: To calculate Tx or Rx rate the pcap trace must contain only Tx or Rx
 *       packets respectively. Otherwise the transmission rate calculated will
 *       be the aggregate of both directions.
 *
 * kontaxis 2015-04-14
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <pcap.h>

#if !__DEBUG__
#define NDEBUG
#endif
#include <assert.h>

/* References:
 *   netinet/ether.h
 *   netinet/ip.h
 *   netinet/tcp.h
 *   netinet/udp.h
 */

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP 0x0800 /* IP */

#if !__NO_ETHERNET__
#define SIZE_ETHERNET sizeof(struct ether_header)
#else
#define SIZE_ETHERNET 0
#endif

/* IP */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))
#define MAX_SIZE_IP (0xF * sizeof(uint32_t))

#define IPVERSION 4

#define IPPROTO_TCP  6
#define IPPROTO_UDP 17

/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th)      (((th)->res1doff & 0xF0) >> 4)
	uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))
#define MAX_SIZE_TCP (0xF * sizeof(uint32_t))

/* UDP */

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__ ((__packed__));

#define MIN_SIZE_UDP (sizeof(struct udphdr))


/* converts 16 bits in host byte order to 16 bits in network byte order */
#if !__BIG_ENDIAN__
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#else
#define h16ton16(n) (n)
#endif

#define n16toh16(n) h16ton16(n)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


int main(int argc, char **argv)
{
	pcap_t * read_handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr header;
	/* Pointer to actual packet */
	const uint8_t * packet;

#if !__NO_ETHERNET__
	struct ether_header * ether;
#endif
	struct my_iphdr * ip;

	/* Off the wire packet size */
	unsigned long total_pkt_bytes;
	/* IPv4 (header + data) packet size */
	unsigned long total_ip4_bytes;

	time_t ts_sec_begin;
	time_t ts_sec_end;

	unsigned long total_pkts_ok;
	unsigned long total_pkts_err;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s trace.pcap\n", argv[0]);
		return -1;
	}

	read_handle = pcap_open_offline(argv[1], errbuf);
	if (read_handle == NULL) {
		fprintf (stderr, "Failed to open \"%s\": %s\n", argv[1], errbuf);
		return 1;
	}

	total_pkt_bytes = 0;
	total_ip4_bytes = 0;

	ts_sec_begin   = 0;
	ts_sec_end     = 0;

	total_pkts_ok  = 0;
	total_pkts_err = 0;

	while ((packet = pcap_next(read_handle, &header)))
	{
		if (unlikely(ts_sec_begin == 0)) {
			ts_sec_begin = header.ts.tv_sec;
		}
		ts_sec_end = header.ts.tv_sec;

#if !__NO_ETHERNET__
		/* Process ethernet header */
		assert(header.caplen >= SIZE_ETHERNET);
		ether = (struct ether_header *) packet;
		if (unlikely(ether->ether_type != h16ton16(ETHERTYPE_IP))) {
#if __DEBUG__
			fprintf(stderr,
				"%lu #%lu WARNING: ether->ether_type != ETHERTYPE_IP. Ignoring.\n",
				header.ts.tv_sec, total_pkts_ok + total_pkts_err + 1);
#endif
			total_pkts_err++;
			continue;
		}
#endif

		/* Process IP header */
		assert(header.caplen >= SIZE_ETHERNET + MIN_SIZE_IP);
		ip = (struct my_iphdr *) (packet + SIZE_ETHERNET);
		if (unlikely(IP_V(ip) != IPVERSION)) {
#if __DEBUG__
			fprintf(stderr, "%lu #%lu WARNING: IP_V(ip) != 4. Ignoring.\n",
				header.ts.tv_sec, total_pkts_ok + total_pkts_err + 1);
#endif
			total_pkts_err++;
			continue;
		}

		total_ip4_bytes += n16toh16(ip->tot_len);
		total_pkt_bytes += header.len;

		total_pkts_ok++;
  }

	pcap_close(read_handle);

	fprintf(stdout,
		"Processed %lu good packets, %lu erroenous between epoch %lu and %lu.\n",
		total_pkts_ok, total_pkts_err, ts_sec_begin, ts_sec_end);

	fprintf(stdout,
		"Counted %lu IPv4 packet bytes or %lu off-the-wire"
		" transmitted in %lu seconds.\n",
		total_ip4_bytes, total_pkt_bytes, ts_sec_end - ts_sec_begin + 1);

	return 0;
}
