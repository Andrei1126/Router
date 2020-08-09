// Micut Andrei-Ion. Grupa 321CB

#include "skel.h"
#include "helpers.h"
#include "queue.h"

size_t route_table_size = 0;
size_t route_table_capacity = INITIAL_CAPACITY;
size_t arp_table_size = 0;
size_t arp_table_capacity = INITIAL_CAPACITY;

// binary search => O (log n) for searching in table routing
route_table get_best_route(uint32_t dest_ip, int start, int end, route_table rtable)
{
	if (end >= start) {
		int mid = (start + end) / 2;

		if ((mid == 0 || (dest_ip & rtable[mid].mask) > rtable[mid - 1].prefix) &&
			rtable[mid].prefix == (dest_ip & rtable[mid].mask)) {
			return &rtable[mid];
		} else if ((dest_ip & rtable[mid].mask) > rtable[mid].prefix) {
			return get_best_route(dest_ip, mid + 1, end, rtable);
		} else {
			return get_best_route(dest_ip, start, mid - 1, rtable);
		}
	}

	return NULL;
}

	// verify the ip for checking where we are and where we should be
arp_table get_arp_entry(uint32_t dest_ip, arp_table arptable)
{
	for (int i = 0; i < arp_table_size; ++i) {
		if (arptable[i].ip == dest_ip) {
			return &arptable[i];
		}
	}

	return NULL;
}

// sort the table to make the binary search
int compare(const void *a, const void *b)
{
	route_table A = (route_table)a;
	route_table B = (route_table)b;
	
	if (A->prefix == B->prefix) {
		return B->mask - A->mask;
	}

	return A->prefix - B->prefix;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init();
	queue q = queue_create();
	route_table rtable = NULL;
	rtable = read_routing_table(rtable);
	packet to_send;
	init_packet(&to_send);

	qsort(rtable, route_table_size, sizeof(struct route_table), compare);

	arp_table arptable = NULL;
	arptable = init_arp_table();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		if (ntohs(eth_hdr->ether_type) == 0x806) { /* ARP ether type code */
			arphdr arp_hdr = (arphdr)(m.payload + sizeof(struct ether_header));

			if (arp_hdr->ar_op == htons(1)) { /* req */
				uint8_t mac_to_find[6];
				uint32_t ip_interface_to_find;
				for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i) {
					ip_interface_to_find = inet_addr(get_interface_ip(i));
					if (arp_hdr->ar_dip == ip_interface_to_find) {
						get_interface_mac(i, mac_to_find);
						break;
					}
				}

				/* Adding the request ip and mac too.. */
				arptable = arptable_push(ntohl(arp_hdr->ar_sip), arp_hdr->ar_sha, arptable);

				/* respoding to the request... */
				memcpy(eth_hdr->ether_shost, mac_to_find, 6);
				memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, 6);
				arp_hdr->ar_op = htons(2); /* arp reply code. */
				memcpy(arp_hdr->ar_dha, arp_hdr->ar_sha, 6);
				memcpy(arp_hdr->ar_sha, mac_to_find, 6);
				arp_hdr->ar_dip = arp_hdr->ar_sip;
				arp_hdr->ar_sip = ip_interface_to_find;

				rc = send_packet(m.interface, &m);
				DIE(rc < 0, "send_packet");
			}
		} else {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			int packet_for_router = 0;
			for (int i = 0; i < 4; ++i) {
				if (ip_hdr->daddr == inet_addr(get_interface_ip(i))) {
					packet_for_router = 1;

					uint8_t mac[6];
					memcpy(mac, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, mac, 6);

					uint32_t aux = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = aux;

					icmp_hdr->type = 0;
					icmp_hdr->code = 0;

					rc = send_packet(i, &m);
					DIE(rc < 0, "send_packet");

					break;
				}
			}

			if (packet_for_router) continue;

			packet m_cpy;
			memcpy(&m_cpy, &m, sizeof(packet));
			queue_enq(q, &m_cpy);

			uint16_t checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));

			if (checksum != 0) continue;

			ip_hdr->ttl--;

			if (ip_hdr->ttl <= 1) {
				packet pkt;
				init_packet(&pkt);
				memcpy(pkt.payload, m.payload, m.len);
				pkt.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				struct ether_header *eth_hdr = (struct ether_header *)pkt.payload; 
				struct iphdr *ip_hdr = (struct iphdr *)(pkt.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				icmp_hdr->type = 11; /* TLE type icmp */
				icmp_hdr-> code = 0;
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->daddr = inet_addr(get_interface_ip(m.interface));
				ip_hdr->ttl = 64;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
				ip_hdr->protocol = IPPROTO_ICMP;

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				rc = send_packet(m.interface, &pkt);
				DIE(rc < 0, "send_packet");

				continue;
			}

			route_table rt = get_best_route(htonl(ip_hdr->daddr), 0, route_table_size - 1, rtable);

			if (rt == NULL) {
				/* We need to send destination unreachable */
				packet pkt;
				init_packet(&pkt);
				memcpy(pkt.payload, m.payload, m.len);
				pkt.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				struct ether_header *eth_hdr = (struct ether_header *)pkt.payload; 
				struct iphdr *ip_hdr = (struct iphdr *)(pkt.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr->type = 3; /* icmp unreachable type */
				icmp_hdr->code = 0;

				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				get_interface_mac(m.interface, eth_hdr->ether_dhost);
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = inet_addr(get_interface_ip(m.interface));
				ip_hdr->protocol = IPPROTO_ICMP;

				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				rc = send_packet(m.interface, &pkt);
				DIE(rc < 0, "send_packet");

				continue;
			}

			ip_hdr->check = 0;
			checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));

			ip_hdr->check = checksum;

			arp_table arpe = get_arp_entry(rt->next_hop, arptable);
			if (arpe) {
				memcpy(eth_hdr->ether_dhost, arpe->mac, 6);
				get_interface_mac(rt->interface, eth_hdr->ether_shost);
				rc = send_packet(rt->interface, &m);
				DIE(rc < 0, "send_packet");
			} else {
				/* we need to create an arp request for the next_hop */

				uint8_t mac[6];
				get_interface_mac(rt->interface, mac);
				memcpy(eth_hdr->ether_shost, mac, 6);
				/* sending the request to the broadcast address */
				uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				memcpy(eth_hdr->ether_dhost, broadcast, 6);
				eth_hdr->ether_type = htons(0x806);

				uint32_t interface_from_ip = inet_addr(get_interface_ip(rt->interface));
				arphdr arp_hdr = craft_arp_request(eth_hdr->ether_shost, interface_from_ip, htonl(rt->next_hop));
				m.len = sizeof(struct ether_header) + sizeof(struct arp_packet);

				memcpy(m.payload + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_packet));

				rc = send_packet(rt->interface, &m);
				DIE(rc < 0, "send_packet");

				/* receiving the packet */
				rc = get_packet(&m);
				DIE(rc < 0, "get_packet");

				arp_hdr = (arphdr)(m.payload + sizeof(struct ether_header));

				arptable = arptable_push(ntohl(arp_hdr->ar_sip), arp_hdr->ar_sha, arptable);

				m = *(packet *)queue_deq(q);
				eth_hdr = (struct ether_header *)m.payload;

				memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, 6);
				eth_hdr->ether_type = htons(0x800);

				rc = send_packet(rt->interface, &m);
				DIE(rc < 0, "send_packet");
			}
		}
	}

	return 0;
}
