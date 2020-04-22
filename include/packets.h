#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include "tables.h" 

/*Builds and returns an ARP Request packet*/
packet build_arp_request_pck(struct iphdr *ip_hdr);

/*Builds and returns an ICMP packet*/
packet build_ICMP_pck(packet recv, int icmp_type, int icmp_code);

/*For every packet in the queue verify if the arp table has a coresponding mac
for that ip adress. If true, then semd the packet to its target. If false put 
the packet back in the queue and verify the next packet*/
void send_waiting_packets();