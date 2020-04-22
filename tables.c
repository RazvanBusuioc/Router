#include "tables.h"

unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned int v = 0;
    
    /* The count of the number of bytes processed. */
    int i;

    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;

        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }

            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return INVALID;
            }
        }
        if (n >= 256) {
            return INVALID;
        }
        v *= 256;
        v += n;
    }
    return v;
}

int cmp_func(const void *a, const void *b){
    /*Sort in a descending manner by mask and by prefix*/
    if ((*(struct routing_table_entry*)b).mask == (*(struct routing_table_entry*)a).mask)
        return (*(struct routing_table_entry*)b).prefix - (*(struct routing_table_entry*)a).prefix;
    else
        return (*(struct routing_table_entry*)b).mask - (*(struct routing_table_entry*)a).mask;
}

int read_rtable(struct routing_table_entry *r_table){
    /*Sets the mask numerator to 0*/
    memset( mask_num, 0, MAX_NR_MASKS * sizeof(unsigned int));

    /*Opens the file to read the route table info*/
    FILE *fptr;
    if((fptr = fopen("rtable.txt", "r")) == NULL){
        printf("Error opening the file!\n Exiting");
        return -1;
    }
    int size = 0;
    char prefix[15];
    char next_hop[15];
    char mask[15];
    char interface[5];

    /*reading every address from a line + the interface*/
    while(fscanf(fptr, "%s", prefix) != EOF){
        fscanf(fptr, "%s", next_hop);
        fscanf(fptr, "%s", mask);
        fscanf(fptr, "%s", interface);
        
        /*converting the string into unsigned int*/
        r_table[size].prefix = ip_to_int(prefix);
        r_table[size].next_hop = ip_to_int(next_hop);
        r_table[size].mask = ip_to_int(mask);
        sscanf(interface, "%d", &r_table[size].interface);

        /*Updating the number of masks like the one parsed*/
        increase_mask_numerator(r_table[size].mask);
        size++;
    }
    /*sorting the route table in O(nlogn)*/
    qsort(r_table, size, sizeof(struct routing_table_entry), cmp_func);

    /*returning the size of the table*/
    return size ;
}


struct routing_table_entry *search_by_mask(unsigned int dest_ip, struct routing_table_entry *r_table){
    int right = 0;
    int left = 0;
    for(int i = 0; i < MAX_NR_MASKS; i++){
        /*For every existing mask in the routing table, do a binary search
        on that interval of masks*/
        if(mask_num[i] == 0) {
            /*There was not found a /(32-i) masks*/
            continue;
        }
        /*At this point there was found a /(32-i) mask*/

        /*Set the intervals for the binary search*/
        right += mask_num[i] - 1;
        struct routing_table_entry *aux = binary_search(dest_ip, r_table, left, right);

        if(aux == NULL){
            /*If there has not been found a match in this interval of masks, 
            set the new interval and continue searching for a match*/
            left = right + 1;
            right += 1;
            continue;
        }

        /*A match has been found*/
        return aux;
    }

    /*No match found at all*/
    return NULL;
}

struct routing_table_entry *binary_search(unsigned int dest_ip, struct routing_table_entry *r_table, int left, int right){
    /*A regular binary search by the prefixes of the routing table*/
    int poz = -1;
    int middle;
	while(left <= right){
		middle = (left + right) / 2;
		if((r_table[middle].prefix & r_table[middle].mask) == (r_table[middle].mask & dest_ip) ){
			poz = middle;
			break;
		}
		else if((r_table[middle].prefix & r_table[middle].mask) > (r_table[middle].mask & dest_ip)){
			left = middle + 1;
		}
		else{
			right = middle - 1;
		}
	}

    if(poz == -1){
        /*A match has not been found*/
        return NULL;
    }

    /*Match found*/
	return &r_table[poz];
}

struct routing_table_entry *linear_search(unsigned int dest_ip, struct routing_table_entry *r_table, int left, int right){
    /*A linear search in the routing table - not used*/
    for(unsigned int i = left; i <= right; i++){
		if((r_table[i].mask & dest_ip) == (r_table[i].prefix & r_table[i].mask)){
			return &r_table[i];
		}
	}
    return NULL;
}

/*Returning a routing table entry that matches the destination ip*/
struct routing_table_entry *get_best_route(unsigned int dest_ip){
	return search_by_mask(dest_ip, r_table);
}

/*Returns the matching arp entry from the arp table.
If a match was not found, return NULL*/
struct arp_entry *get_arp_entry(unsigned int ip){
	int i;
	for(i = 0; i < arp_table_len; i++){
		if(arp_table[i].ip == ip)
			return &arp_table[i];
	}
	return NULL;
}

/*Add an arp entry to the arp table. If the entry already exists, stop*/
void add_arp_entry(struct arp_entry arp_entry){
	if(get_arp_entry(arp_entry.ip) != NULL)
		return;
	arp_table[arp_table_len] = arp_entry;
	arp_table_len++;
}

void increase_mask_numerator(unsigned int mask){
    for(int i = 0; i < MAX_NR_MASKS; i++){
        /*Compute every possible mask and compare it to the one given as
        parameter. If equal, increase the number of suck masks*/
        unsigned int compute_mask = 0;
        for(int j = 0; j <= i; j++){
           compute_mask += 1<<(31 - j);
        }
        if(mask == compute_mask){
            mask_num [MAX_NR_MASKS - i - 1]++;
            return;
        }
    }
}