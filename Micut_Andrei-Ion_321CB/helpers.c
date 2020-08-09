// Micut Andrei-Ion. Grupa 321CB

#include "helpers.h"

extern size_t route_table_size;
extern size_t route_table_capacity;
extern size_t arp_table_size;
extern size_t arp_table_capacity;

	// initialise the routing table
route_table init_routing_table()
{
	route_table rtable = (route_table)malloc(route_table_capacity * sizeof(struct route_table));

	DIE(rtable == NULL, "malloc");
	route_table_size = 0;

	return rtable;
}

	// read from file into routing table
route_table read_routing_table(route_table rtable)
{

	char stream[MAX_STRING];

	FILE *f = fopen("rtable.txt", "r");

	DIE(f == NULL, "fopen");

	if (rtable == NULL) {
		rtable = init_routing_table();
	}

	while(fgets(stream, MAX_STRING, f)) {
		int cnt = 0;
		char *token = strtok(stream, " \n");

		while (token) {

			if (cnt == 0) {
				rtable[route_table_size].prefix = ntohl(inet_addr(token));
			} else if (cnt == 1) {
				rtable[route_table_size].next_hop = ntohl(inet_addr(token));
			} else if (cnt == 2) {
				rtable[route_table_size].mask = ntohl(inet_addr(token));
			} else if (cnt == 3) {
				rtable[route_table_size++].interface = atoi(token);
				cnt = 0;
			}
			cnt++;
			token = strtok(NULL, " \n");
		}
		if (route_table_size >= route_table_capacity) {
			route_table_capacity *= 2;

			rtable = realloc(rtable, route_table_capacity * sizeof(struct route_table));

			DIE(rtable == NULL, "realloc");
		}
	}

	return rtable;
}

	// initialise the arp table
arp_table init_arp_table()
{
	arp_table arptable = (arp_table)malloc(arp_table_capacity * sizeof(struct arp_table));

	DIE(arptable == NULL, "malloc");

	return arptable;
}

	// the arp table updates at any request and reply of ARP
arp_table arptable_push(uint32_t ip, uint8_t mac[6], arp_table arptable)
{
	arptable[arp_table_size].ip = ip;
	memcpy(arptable[arp_table_size++].mac, mac, 6);

	if (arp_table_size >= arp_table_capacity) {
		arp_table_capacity *= 2;
		arptable = realloc(arptable, arp_table_capacity * sizeof(struct arp_table));

		DIE(arptable == NULL, "realloc");
	}

	return arptable;
}

arphdr craft_arp_request(uint8_t sha[6], uint32_t source_ip, uint32_t dest_ip)
{
	arphdr arp_hdr = calloc(1, sizeof(struct arp_packet));

	arp_hdr->ar_hrd = htons(1); /* hw address space = 1. */
	arp_hdr->ar_pro = htons(0x800); /* proto address space = 0x800. */
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(1); /* arp request code */
	memcpy(arp_hdr->ar_sha, sha, 6);
	arp_hdr->ar_sip = source_ip;
	arp_hdr->ar_dip = dest_ip;

	return arp_hdr;
}

	// initialise the pachet
void init_packet(packet *pkt)
{
	memset(pkt->payload, 0, sizeof(pkt->payload));
	pkt->len = 0;
}

	// calculate the ip checksum
uint16_t ip_checksum(void* vdata, size_t length) {
	
	// Cast the data pointer to one that can be indexed.
	char* data = (char *) vdata;

	// Initialise the accumulator.
	uint64_t acc = 0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset = ((uintptr_t) data) & 3;
	
	if (offset) {
		size_t count = 4 - offset;
		if (count>length) count = length;
		uint32_t word = 0;
		
		memcpy(offset + (char *) &word, data, count);
		
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	// Handle any complete 32-bit blocks.
	char *data_end = data + (length & ~3);
	
	while (data != data_end) {
		uint32_t word;
		
		memcpy(&word, data, 4);
		
		acc += ntohl(word);
		
		data += 4;
	}
	
	length &= 3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	// Handle deferred carries.
	
	acc = (acc & 0xffffffff) + (acc >> 32);
	
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}
