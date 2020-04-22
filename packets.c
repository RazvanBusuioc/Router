#include "packets.h"


/*Builds and returns an ARP Request packet*/
packet build_arp_request_pck(struct iphdr *ip_hdr){
	packet arp_req;

	/*The interface to send the packet on*/
	int interface = (get_best_route(ntohl(ip_hdr->daddr)))->interface;

	/*Packet fields*/
	arp_req.len = ETH_HSIZE + ARP_HSIZE;
	arp_req.interface = interface;

	/*Pointing the headers to the packet that we want to build*/
	struct ether_header *req_eth = (struct ether_header*)arp_req.payload;
	struct ether_arp *req_arp = (struct ether_arp*)(arp_req.payload + ETH_HSIZE);

	/*Completing the ETHER and ARP headers*/
	req_eth->ether_type = htons(ETHERTYPE_ARP);
	req_arp->arp_op = htons(ARPOP_REQUEST);
	req_arp->arp_pln = IPV4_SIZE;
	req_arp->arp_hln = MAC_SIZE;
	req_arp->arp_hrd = htons(ARPHRD_ETHER);
	req_arp->arp_pro = htons(ETHERTYPE_IP);
	get_interface_mac(interface, req_eth->ether_shost);
	get_interface_mac(interface, req_arp->arp_sha);
	memset(req_eth->ether_dhost, 0xff, MAC_SIZE);
	memset(req_arp->arp_tha, 0, MAC_SIZE);
	unsigned int ipInt = htonl(ip_to_int(get_interface_ip(interface)));
	memcpy(&req_arp->arp_spa, &ipInt, IPV4_SIZE);
	memcpy(&req_arp->arp_tpa, &ip_hdr->daddr, IPV4_SIZE);

	return arp_req;
}

/*Builds and returns an ICMP packet*/
packet build_ICMP_pck(packet recv, int icmp_type, int icmp_code){
	packet icmp_pck;

	/*Packet fields*/
	icmp_pck.len = ETH_HSIZE + IP_HSIZE + ICMP_HSIZE;
	icmp_pck.interface = recv.interface;

	/*Pointing the headers to our recieved packet "recv"*/
	struct ether_header *eth_hdr_recv = (struct ether_header *)icmp_pck.payload;
	struct iphdr *ip_hdr_m = (struct iphdr *)(icmp_pck.payload + ETH_HSIZE);

	/*Pointing the headers to the ICMP packet that we want to build*/
	struct ether_header *eth_hdr = (struct ether_header *)icmp_pck.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(icmp_pck.payload + ETH_HSIZE);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_pck.payload + ETH_HSIZE + IP_HSIZE);

	/*Completing the ETHER, IP and ICMP headers*/
	memcpy(&eth_hdr->ether_shost, &eth_hdr_recv->ether_dhost, MAC_SIZE);
	memcpy(&eth_hdr->ether_dhost, &eth_hdr_recv->ether_shost, MAC_SIZE);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	ip_hdr->version = IPV4_SIZE;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(IP_HSIZE + ICMP_HSIZE);
	ip_hdr->id = htons(0);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->daddr = ip_hdr_m->saddr;
	ip_hdr->saddr = htonl(ip_to_int(get_interface_ip(recv.interface)));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, IP_HSIZE);
	icmp_hdr->code = icmp_code;
	icmp_hdr->type = icmp_type;
	icmp_hdr->un.echo.id = 0;
	icmp_hdr->un.echo.sequence = 1;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, ICMP_HSIZE)	;

	return icmp_pck;
}

/*For every packet in the queue verify if the arp table has a coresponding mac
for that ip adress. If true, then semd the packet to its target. If false put 
the packet back in the queue and verify the next packet*/
void send_waiting_packets(){
	int i;
	for(i = 0; i < queue_len; i++){
		/*Extraxt the first packet in the queue*/
		packet *p = (packet *)queue_deq(q);
		queue_len--;

		/*Point the ETHER and IP headers to the packet*/
		struct ether_header *eth_hdr = (struct ether_header *)p->payload;
		struct iphdr *ip_hdr = (struct iphdr *)(p->payload + ETH_HSIZE);
		if(get_arp_entry(ip_hdr->daddr) != NULL){
			/*There has been found a mac adress coresponding to the dest ip adress
			Modify the eth header and send the packet*/
			memcpy(&eth_hdr->ether_shost, &eth_hdr->ether_dhost, MAC_SIZE);
			memcpy(&eth_hdr->ether_dhost, get_arp_entry(ip_hdr->daddr)->mac, MAC_SIZE);
			send_packet((get_best_route(ntohl(ip_hdr->daddr)))->interface, p);
		}else{
			/*There hasn`t been found a mac adress coresponding to the dest ip adress
			Put the packet back in the queue*/
			queue_enq(q, p);
			queue_len++;
		}
	}
}