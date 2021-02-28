#include <fcntl.h>

#define MAX_RTABLE_SIZE 100000

struct route {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

struct	ether_arp {
			struct	arphdr ea_hdr;		/* fixed-size header */
			uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */ //mac
			uint8_t arp_spa[4];		/* sender protocol address */ //ip-ul
			uint8_t arp_tha[ETH_ALEN];	/* target hardware address */ //mac
			uint8_t arp_tpa[4];		/* target protocol address */ //ip-ul destinatie
};

int read_routing_table(struct route *rtable);
