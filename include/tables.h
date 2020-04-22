#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include "skel.h"
#include "queue.h"
#define MAX_NR_MASKS 32


struct routing_table_entry{
    unsigned int prefix;
    unsigned int next_hop;
    unsigned int mask;
    int interface;
};

struct arp_entry{
    unsigned int ip;
    uint8_t mac[MAC_SIZE];
};

/*This struct holds the number of occurrences of a certain massk(e.g. /24 )
in the routing table*/
struct mask_numerator{
    unsigned int mask;
    int nr;
};
/*mask_num[0] = /32 mask .... mask_num[31] = /1 mask*/
unsigned int mask_num[MAX_NR_MASKS];

/*Routing table and its length*/
struct routing_table_entry *r_table;
int rtable_len;

/*ARP table and its length*/
struct arp_entry *arp_table;
int arp_table_len;

/*Queue for storing the waiting to be sent packets*/
queue q;
int queue_len;

/*returns the size of the table*/
int read_rtable(struct routing_table_entry *r_table);

/*cmp function for the q sort - sorting the table in descending order by the mask and prefix*/
int cmp_func(const void *a, const void *b);

/*converst ip string into unsigned int ip*/
unsigned int ip_to_int (const char * ip);

/*binary search for the longest prefix match of the destination ip
Complexity: O(logn)
USED*/
struct routing_table_entry *binary_search(unsigned int dest_ip, struct routing_table_entry *r_table, int left, int right);

/*Linear search for the longest prefix match of the destination ip
Complexity: O(n)
NOT USED*/
struct routing_table_entry *linear_search(unsigned int dest_ip, struct routing_table_entry *r_table, int left, int right);

/*Calling the binary search function for every chunk of masks in the table*/
struct routing_table_entry *search_by_mask(unsigned int dest_ip, struct routing_table_entry *r_table);

/*Returning a routing table entry that matches the destination ip*/
struct routing_table_entry *get_best_route(unsigned int dest_ip);

/*Returns the matching arp entry from the arp table.
If a match was not found, return NULL*/
struct arp_entry *get_arp_entry(unsigned int ip);

/*Add an arp entry to the arp table. If the entry already exists, stop*/
void add_arp_entry(struct arp_entry arp_entry);

/*Increase the numerator for this particular mask given as a parameter*/
void increase_mask_numerator(unsigned int mask);

