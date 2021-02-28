#include <fcntl.h>

#define MAX_ARPTABLE_SIZE 1000

struct arp_entry {
	uint32_t ip_addr;
	uint8_t mac_addr[6];
};

