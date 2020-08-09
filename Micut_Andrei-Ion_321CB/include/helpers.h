// Micut Andrei-Ion. Grupa 321CB

#include "skel.h"
#include <string.h>

#define INITIAL_CAPACITY 300
#define MAX_STRING        64

#ifndef __HELPERS__H__
#define __HELPERS__H__ 1

typedef struct route_table {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} *route_table;

typedef struct __attribute__((__packed__)) arp_packet {
	unsigned short int ar_hrd;	    	/* Format of hardware address.  */
    unsigned short int ar_pro;	    	/* Format of protocol address.  */
    unsigned char ar_hln;		        /* Length of hardware address.  */
    unsigned char ar_pln;	        	/* Length of protocol address.  */
    unsigned short int ar_op;	    	/* ARP opcode (command).  */
    unsigned char ar_sha[6];	/* Sender hardware address.  */
    uint32_t ar_sip;	    	/* Sender IP address.  */
    unsigned char ar_dha[6];	/* Target hardware address.  */
    uint32_t ar_dip;	    	/* Target IP address.  */
} *arphdr;

typedef struct arp_table {
	uint32_t ip;
	uint8_t mac[6];
} *arp_table;

route_table init_routing_table();
arp_table init_arp_table();
route_table read_routing_table(route_table rtable);
arp_table arptable_push(uint32_t ip, uint8_t mac[6], arp_table arptable);
uint16_t ip_checksum(void* vdata, size_t length);
void init_packet(packet *pkt);
arphdr craft_arp_request(uint8_t sha[6], uint32_t source_ip, uint32_t dest_ip);
#endif
