#include "skel.h"
#include "routing_table.h"
#include "arp_table.h"
#include "constants.h"
#include "queue.h"

struct route *rtable;
struct arp_entry *arptable;
int rtable_size;
int arptable_size;

struct route *get_best_route(uint32_t dest_ip) {
	int max_prefix = 0;
	struct route* best_match = NULL;
	int left = 0;
	int right = rtable_size - 1;
    int mid; 
	while (left <= right) { 
  		mid = (left + right) / HALF; 

        if ((rtable[mid].prefix & rtable[mid].mask) == (dest_ip & rtable[mid].mask)) {
            if (rtable[mid].mask > max_prefix) {
            	max_prefix = rtable[mid].mask;
            	best_match = &rtable[mid];
            }
            left = mid + 1;
        }  

        if ((rtable[mid].prefix & rtable[mid].mask) <= (dest_ip & rtable[mid].mask)) { 
            left = mid + 1; 
        } else {
            right = mid - 1; 
        }
    } 
	return best_match;
}

struct arp_entry *get_arp_entry(uint32_t ip) {
    for (int i = 0; i < arptable_size; ++i) {
    	if (arptable[i].ip_addr == ip) {
    		return &arptable[i];
    	}
    }
    return NULL;
}

void add_arp_entry(packet *m) {
	struct ether_arp *arp_hdr = (struct ether_arp *)(m -> payload +
		sizeof(struct ether_header));
	memcpy(&arptable[arptable_size].ip_addr, &arp_hdr -> arp_spa,
		sizeof(uint32_t));
	memcpy(arptable[arptable_size].mac_addr, arp_hdr -> arp_sha,
		sizeof(uint8_t) * ETH_ALEN);
	arptable_size++;
}

int comparator(const void *x, const void *y) { 
    const struct route *a = x;
    const struct route *b = y;
    int comp = a -> prefix - b -> prefix;
    if (comp < 0) {
    	return -1;
    }
    if (comp > 0) {
    	return 1;
    }
    if (a -> mask > b -> mask) {
    	return 1;
    }
    return -1;
} 

void print_loaded() {
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~READY~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~TO~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ROCK~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("\n");
}

// Checks if the packet is ARP and also if it is for this router.
bool checkARPforMe(packet *m) {
	struct ether_header *eth_hdr = (struct ether_header *) m -> payload;
	if (htons(eth_hdr->ether_type) == ETH_P_ARP) {
		// We know that the ip on interfaces is like this: XXX.XXX.X.X
		struct ether_arp *arp_hdr = (struct ether_arp *)(m -> payload +
			sizeof(struct ether_header));
		char *ip = get_interface_ip(m->interface);
		return (atoi(strtok(ip, ".")) == arp_hdr->arp_tpa[FIRST_BYTE] && 
			atoi(strtok(NULL, ".")) == arp_hdr->arp_tpa[SECOND_BYTE] &&
			atoi(strtok(NULL, ".")) == arp_hdr->arp_tpa[THIRD_BYTE] && 
			atoi(strtok(NULL, ".")) == arp_hdr->arp_tpa[FOURTH_BYTE]);
	}
	return false;
}

bool checkARP_Request(packet *m) {
	struct ether_arp *arp_hdr = (struct ether_arp *)(m -> payload +
		sizeof(struct ether_header));
	return (htons(arp_hdr -> ea_hdr.ar_op) == ARPOP_REQUEST);
}

bool checkARP_Reply(packet *m) {
	struct ether_arp *arp_hdr = (struct ether_arp *)(m -> payload +
		sizeof(struct ether_header));
	return (htons(arp_hdr -> ea_hdr.ar_op) == ARPOP_REPLY);
}

void sendARP_Reply(packet *m) {
	struct ether_header *eth_hdr = (struct ether_header *) m -> payload;
	struct ether_arp *arp_hdr = (struct ether_arp *)(m -> payload +
		sizeof(struct ether_header));

	// Modify ETH header.
	memcpy(eth_hdr -> ether_dhost, eth_hdr -> ether_shost, ETH_ALEN);
	get_interface_mac(m -> interface, eth_hdr -> ether_shost);		
	
	// Modify ARP addresses.
	memcpy(arp_hdr -> arp_tha, arp_hdr -> arp_sha, sizeof(arp_hdr -> arp_sha));
	get_interface_mac(m -> interface, arp_hdr -> arp_sha);
	uint8_t aux[4];
	memcpy(aux, arp_hdr -> arp_tpa, sizeof(arp_hdr -> arp_tpa));
	memcpy(arp_hdr -> arp_tpa, arp_hdr -> arp_spa, sizeof(arp_hdr -> arp_tpa));
	memcpy(arp_hdr -> arp_spa, aux, sizeof(arp_hdr -> arp_tpa));
	// Modify operation field.
	arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);

	send_packet(m -> interface, m);
}

// Checks if it is an IP packet.
bool checkIP(packet *m) {
	struct ether_header *eth_hdr = (struct ether_header *) m -> payload;
	return (htons(eth_hdr -> ether_type) == ETH_P_IP);
}

bool check_ip_checksum(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	int oldCheck = ip_hdr -> check;
	ip_hdr -> check = 0;
	return (oldCheck == checksum(ip_hdr, sizeof(struct iphdr)));
}

bool checkICMP(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	return (ip_hdr -> protocol == IPPROTO_ICMP);
}

bool checkECHO(packet *m) {
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m -> payload +
		sizeof(struct ether_header) + sizeof(struct iphdr));
	return (icmp_hdr -> type == ICMP_ECHO);
}

bool matchAddr_echo(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	return (ip_hdr -> daddr == inet_addr(get_interface_ip(m -> interface)));
}

int sendICMP(packet *m, uint8_t icmp_type) {
	packet *reply = malloc(sizeof(packet));
	memset(reply -> payload, 0, sizeof(reply -> payload));
	reply -> interface = m -> interface;
	reply -> len = sizeof(struct ether_header) + sizeof(struct iphdr) +
		sizeof(struct icmphdr);

	// Set Ethernet header.
	struct ether_header *eth_hdr = (struct ether_header *) reply -> payload;
	struct ether_header *eth_hdr_old = (struct ether_header *) m -> payload;
	memcpy(eth_hdr -> ether_dhost, eth_hdr_old -> ether_shost, ETH_ALEN);
	get_interface_mac(m -> interface, eth_hdr -> ether_shost);
	eth_hdr -> ether_type = htons(ETH_P_IP);

	// Set IP header.
	struct iphdr *ip_hdr = (struct iphdr *)(reply -> payload + sizeof(struct ether_header));
	struct iphdr *ip_hdr_old = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	memcpy(&(ip_hdr -> daddr), &(ip_hdr_old -> saddr), sizeof(ip_hdr -> daddr));
	ip_hdr -> saddr = inet_addr(get_interface_ip(m -> interface));
	ip_hdr -> ihl = DEFAULT_IHL;
	ip_hdr -> tos = DEFAULT_TOS;
	ip_hdr -> frag_off = DEFAULT_FRAG_OFF;
	ip_hdr -> version = DEFAULT_IP_VERSION;
	ip_hdr -> tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr -> id = ip_hdr_old -> id;
	ip_hdr -> ttl = DEFAULT_TTL;
	ip_hdr -> protocol = IPPROTO_ICMP;
	ip_hdr -> check = 0;
	ip_hdr -> check = checksum(ip_hdr, sizeof(struct iphdr));

	// Set ICMP header.
	struct icmphdr *icmp_hdr = (struct icmphdr *)(reply -> payload +
		sizeof(struct ether_header) + sizeof(struct iphdr));
	struct icmphdr *icmp_hdr_old = (struct icmphdr *)(m -> payload +
		sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr -> code = DEFAULT_ICMP_CODE;
	icmp_hdr -> type = icmp_type;
	icmp_hdr -> un.echo.id = icmp_hdr_old -> un.echo.id;
	icmp_hdr -> un.echo.sequence = icmp_hdr_old -> un.echo.sequence;
	icmp_hdr -> checksum = 0;
	icmp_hdr -> checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

	int r = send_packet(reply -> interface, reply);
	free(reply);
	return r;
}

bool checkTTL(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	return (ip_hdr -> ttl > 1);
}

int sendARP_Request(struct route *best_route) {
	int interface = best_route -> interface;
	packet *req = malloc(sizeof(packet));
	memset(req -> payload, 0, sizeof(req -> payload));
	req -> interface = best_route -> interface;
	req -> len = sizeof(struct ether_header) + sizeof(struct ether_arp);

	// Set ETH header.
	struct ether_header *eth_hdr = (struct ether_header *) req -> payload;
	memset(eth_hdr -> ether_dhost, MAX_BYTE, sizeof(uint8_t) * ETH_ALEN);
	get_interface_mac(req -> interface, eth_hdr -> ether_shost);	
	eth_hdr -> ether_type = htons(ETH_P_ARP);

	
	// Set ARP header.
	struct ether_arp *arp_hdr = (struct ether_arp *)(req -> payload +
		sizeof(struct ether_header));
	// MAC addresses.
	memset(arp_hdr -> arp_tha, MAX_BYTE, sizeof(uint8_t) * ETH_ALEN);
	get_interface_mac(req -> interface, arp_hdr -> arp_sha);
	// IP addresses.
	char *ip = get_interface_ip(interface);
	(arp_hdr -> arp_spa)[FIRST_BYTE] = atoi(strtok(ip, "."));
	(arp_hdr -> arp_spa)[SECOND_BYTE] = atoi(strtok(NULL, "."));
	(arp_hdr -> arp_spa)[THIRD_BYTE] = atoi(strtok(NULL, "."));
	(arp_hdr -> arp_spa)[FOURTH_BYTE] = atoi(strtok(NULL, "."));
	memcpy(&arp_hdr->arp_tpa, &best_route -> next_hop, sizeof(uint32_t));
	
	// Set ohter fields.
	arp_hdr -> ea_hdr.ar_op = htons(ARPOP_REQUEST);
	arp_hdr -> ea_hdr.ar_hrd = htons(FORMAT_ARP_HARD);
	arp_hdr -> ea_hdr.ar_hln = LEN_HARD_ADDR_ARP;
	arp_hdr -> ea_hdr.ar_pln = LEN_PROT_ADD_ARP;
	arp_hdr -> ea_hdr.ar_pro = FORMAT_PROT_ADDR_ARP;

	int r = send_packet(req -> interface, req);  
	free(req);
	return r;
}

bool has_arp_entry(packet *old_packet) {
	struct iphdr *ip_hdr = (struct iphdr *)(old_packet -> payload +
		sizeof(struct ether_header));
	if (get_arp_entry(ip_hdr -> daddr) == NULL) {
		return false;
	}
	return true;
}

int forward_packet(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	
	// Don't we have in ARP entry for it?
	struct arp_entry *arpEntry = get_arp_entry(ip_hdr -> daddr);
	if (arpEntry == NULL) {
		struct route *best_route = get_best_route(ip_hdr -> daddr);
		sendARP_Request(best_route);
		return NO_ARP_ENTRY;
	} 
	
	// Modify IP header.
	ip_hdr -> ttl--;
	ip_hdr -> check = 0;
	ip_hdr -> check = checksum(ip_hdr, sizeof(struct iphdr));
	
	// Modify ETH header.
	struct ether_header *eth_hdr = (struct ether_header *) m -> payload;
	get_interface_mac(m -> interface, eth_hdr -> ether_shost);
	memcpy(eth_hdr -> ether_dhost, arpEntry -> mac_addr, ETH_ALEN);
	
	struct route *best_route = get_best_route(ip_hdr -> daddr);
	m -> interface = best_route -> interface;

	int s = send_packet(m -> interface, m);
	return s;
}

bool check_destReachable(packet *m) {
	struct iphdr *ip_hdr = (struct iphdr *)(m -> payload + sizeof(struct ether_header));
	if (get_best_route(ip_hdr -> daddr) == NULL) {
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[]) {

	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	init();
	
	rtable = malloc(sizeof(struct route) * MAX_RTABLE_SIZE);
	DIE(rtable == NULL, "Error: not enough memory for Routing Table.\n");
	arptable = malloc(sizeof(struct arp_entry) * MAX_ARPTABLE_SIZE);
	DIE(arptable == NULL, "Error: not enough memory for ARP Table.\n");
	rtable_size = read_routing_table(rtable);
	qsort(rtable, rtable_size, sizeof(struct route), comparator);
	queue q = queue_create();
	arptable_size = 0;
	// print_loaded();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
		if (checkARPforMe(&m)) {					// Is it ARP?
			if (checkARP_Request(&m)) { 				// Is it ARP REQUEST?
				sendARP_Reply(&m); 
			} else if (checkARP_Reply(&m)) {	 		// Is it ARP REPLY?
				add_arp_entry(&m);							// Add entry to ARP table.
				while (!queue_empty(q)) {
					packet *old_packet = front(q);
					if (has_arp_entry(old_packet)) {        // Do we have entry now?
						forward_packet(old_packet);				// Forward packet again.
						free(queue_deq(q));
					} else {
						continue;
					}
				}
			} 
		} else if (checkIP(&m)) { 					// Is it IP?
			if (!check_ip_checksum(&m)) { 				// Is it not corrupted?
				fprintf(stderr, "Corrupted IP Packet.\n");
				continue;
			}
			if (matchAddr_echo(&m)) { 					// Is it for me?
				if (checkICMP(&m)) { 						// Is it ICMP?
					if (checkECHO(&m)) { 						// Is it ICMP ECHO?
						sendICMP(&m, ICMP_ECHOREPLY);
						continue;
					}
				} 
			} else {									// Is it not for me?
				if (!checkTTL(&m)) {						// Is TTL <= 1?
					sendICMP(&m, ICMP_TIME_EXCEEDED);
					continue;
				}
				if (check_destReachable(&m)) {             // Is it reachable?
					int r = forward_packet(&m);
					if (r == NO_ARP_ENTRY) {					// Am i not having the ARP entry
						packet *new = malloc(sizeof(packet));	// for it?
						memcpy(new, &m, sizeof(packet));
						queue_enq(q, new);
					}
				} else {									// Is it not reachable?
					sendICMP(&m, ICMP_DEST_UNREACH);
				}
			}
		} 
	}
	free(q);
	free(rtable);
	free(arptable);
}
