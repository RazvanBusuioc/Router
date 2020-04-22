#include "packets.h"

int main(int argc, char *argv[])	
{
	packet m;
	int rc;
	/*UINTs used for storing IPV4 adresses*/
	unsigned int target_ip;
	unsigned int sender_ip;
	unsigned int auxUInt;
	/*queue for packets that can`t be sent at a specific time because
	there is no mac adress in the arp table for the destination*/
	q = queue_create();
	queue_len = 0;

	init();

	r_table = malloc(TABLE_MAX_SIZE * sizeof(struct routing_table_entry));
	rtable_len = read_rtable(r_table);
	arp_table = malloc(TABLE_MAX_SIZE * sizeof(struct arp_entry));
	arp_table_len = 0;

	while (1) {	
		/*Recieved a packet. Time to inspect it*/	
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
			/*The packet recieved is an ARP packet
			Point the ARP header to the payload of the pck*/
			struct ether_arp *eth_arp_header = (struct ether_arp * )(m.payload + ETH_HSIZE);

			/*Initialize the IP of the sender and target in UINT_32*/
			memcpy(&target_ip,eth_arp_header->arp_tpa,IPV4_SIZE);
			memcpy(&sender_ip,eth_arp_header->arp_spa,IPV4_SIZE);
			target_ip = ntohl(target_ip);
			sender_ip = ntohl(sender_ip);

		  	if( ntohs(eth_arp_header->arp_op) == ARPOP_REQUEST && target_ip == ip_to_int(get_interface_ip(m.interface))){
				/*The packet recieved is an ARP Request for the router*/
				/*Change the eth and arp headers of the packet in order to
				convert it to an ARP Reply.*/ 
				eth_arp_header->arp_op = htons(ARPOP_REPLY);

				/*Set the source and destination mac adress*/
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_SIZE );
				memcpy(eth_arp_header->arp_tha, eth_hdr->ether_shost, MAC_SIZE);
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				get_interface_mac(m.interface, eth_arp_header->arp_sha);

				/*Set the source and target IP adress*/
				auxUInt = ntohl(ip_to_int (get_interface_ip(m.interface)));
				memcpy(eth_arp_header->arp_spa, &auxUInt, IPV4_SIZE);
				memcpy(eth_arp_header->arp_tpa, &auxUInt, IPV4_SIZE);

				/*Send the ARP Reply back to the requester*/
				send_packet(m.interface, &m);
				continue;
			}
			else if (ntohs(eth_arp_header->arp_op) == ARPOP_REPLY && sender_ip != ip_to_int(get_interface_ip(m.interface))){
				/*The packet recieved is and ARP Reply*/
				/*Construct an arp entry in order to store it in the ARP table*/
				struct arp_entry this_arp;
				memcpy(&this_arp.ip, &eth_arp_header->arp_spa, IPV4_SIZE);
				memcpy(&this_arp.mac, &eth_arp_header->arp_sha, MAC_SIZE);

				/*Store the entry in the ARP table*/
				add_arp_entry(this_arp);

				/*Send any waiting(for the mac adress) packets*/
				send_waiting_packets();

			}
		}
		else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			/*The packet recieved is an IP packet
			Point the IP header to the payload of the pck*/
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + ETH_HSIZE);

			if(ip_hdr->protocol == IPPROTO_ICMP){
				/*The packet recieved is also an ICMP packet
				Point the ICMP header to the payload of the pck*/
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ETH_HSIZE + IP_HSIZE);

				if(icmp_hdr->type == ICMP_ECHO && ntohl(ip_hdr->daddr) == ip_to_int(get_interface_ip(m.interface))){
					/*The ICMP ECHO Request packet has the router as its destination*/
					if(checksum(ip_hdr, IP_HSIZE) != 0 || checksum(icmp_hdr, ICMP_HSIZE) != 0){
						/*Wrong checksum either for the IP header or ICMP header*/
						continue;
					}
					/*Update the ICMP header type field to echo reply*/
					icmp_hdr->type = ICMP_ECHOREPLY;

					/*Change the source and destination adresses from both
					ether and IP headers*/
					memcpy(&ip_hdr->daddr,&ip_hdr->saddr, IPV4_SIZE);
					memcpy(&eth_hdr->ether_dhost, &eth_hdr->ether_shost, MAC_SIZE);
					ip_hdr->saddr = htonl(ip_to_int(get_interface_ip(m.interface)));
					get_interface_mac(m.interface, eth_hdr->ether_dhost);

					/*Update ttl*/
					ip_hdr->ttl = 64;

					/*Update checksum for IP header*/
					ip_hdr->check = 0;
					ip_hdr->check = checksum(ip_hdr, IP_HSIZE);

					/*Update checksum for ICMP header*/
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = checksum(icmp_hdr, ICMP_HSIZE);

					/*Send back the packet on the best route*/
					send_packet((get_best_route(ntohl(ip_hdr->daddr)))->interface,&m);
					continue;
				}

			}
			if(checksum(ip_hdr, IP_HSIZE) != 0){
				/*Wrong checksum, throw the packet*/
				 continue;
			}

			/*Decrease ttl*/
			ip_hdr->ttl--;

			if(ip_hdr->ttl <= 0){
				/*Invalid ttl. Build an ICMP time exceeded packet and send it
				back to the source*/ 
				packet time_exc = build_ICMP_pck(m, ICMP_TIME_EXCEEDED, 0);
				send_packet((get_best_route(ntohl(ip_hdr->saddr)))->interface, &time_exc);
				continue;
			}

			/*Recalculate checksum after ttl decrementation */
			incremental_updating_checksum(ip_hdr);

			if(get_best_route(ntohl(ip_hdr->daddr)) == NULL){
				/*No path available in the routing table for this ip
				Send a Dest Unreachable ICMP packet*/
				packet host_unreach = build_ICMP_pck(m, ICMP_DEST_UNREACH, 0);
				send_packet((get_best_route(ntohl(ip_hdr->saddr)))->interface, &host_unreach);
				continue;
			}

			if(get_arp_entry(ip_hdr->daddr) != NULL){
				/*There is a mac adress in the ARP table that matches the 
				destination IP adress*/
				/*Change the ether header adresses*/
				memcpy(&eth_hdr->ether_shost, &eth_hdr->ether_dhost, MAC_SIZE);
				memcpy(&eth_hdr->ether_dhost, get_arp_entry(ip_hdr->daddr)->mac, MAC_SIZE);
				
				/*Send the packet to the best route*/
				send_packet((get_best_route(ntohl(ip_hdr->daddr)))->interface, &m);
			}else{
				/*There is not a mac adress in the ARP table that matches the
				destination IP adress*/
				/*Copy the actual packet and store it in a queue*/
				packet copy;
				memcpy(&copy,&m, sizeof(m));
				queue_enq(q, &copy);
				queue_len ++;
				
				/*Construct an ARP Request packet and send it to the best route
				in order to obtain the mac adress of the destination*/
				//int interface_for_arp = (get_best_route(ntohl(ip_hdr->daddr)))->interface;
				packet arp_req = build_arp_request_pck(ip_hdr);
				send_packet((get_best_route(ntohl(ip_hdr->daddr)))->interface, &arp_req);
			}				
		}
	}
	free(r_table);
	free(arp_table);
}
