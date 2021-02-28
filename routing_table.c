#include "skel.h"
#include "routing_table.h"

int read_routing_table(struct route *rtable) {
	int fd = open("rtable.txt", O_RDONLY);
	DIE (fd == -1, "Error reading the routing table.\n");

	int is_reading = 1;
	int counter = 0;
	int char_count = 0; 
	char addr[16];
	while (is_reading > 0) {
		char c = 0;
		int identifier = 0;
		while (c != '\n') {
			is_reading = read(fd, &c, sizeof(char));
			if (is_reading <= 0) {
				break;
			}
			addr[char_count++] = c;
			if (c == ' ' || c == '\n') {
				if (identifier == 0) {
					addr[char_count - 1] = '\0';
					rtable[counter].prefix = inet_addr(addr);
					identifier++;
					addr[char_count - 1] = addr[char_count - 2];
					char_count = 0;
				} else if (identifier == 1) {
					addr[char_count - 1] = '\0';
					rtable[counter].next_hop = inet_addr(addr);
					identifier++;
					addr[char_count - 1] = addr[char_count - 2];
					char_count = 0;
				} else if (identifier == 2) {
					addr[char_count - 1] = '\0';
					rtable[counter].mask = inet_addr(addr);
					identifier++;
					addr[char_count - 1] = addr[char_count - 2];
					char_count = 0;
				} else if (identifier == 3) {
					addr[char_count - 1] = '\0';
					rtable[counter].interface = atoi(addr);
					addr[char_count - 1] = addr[char_count - 2];
					char_count = 0;
					identifier = 0;
					counter++;
				}
			}
		}
	}
	return counter;
}