//  pcap_throughput
//   reads in a pcap file and outputs basic throughput statistics 

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "uthash-master/src/uthash.h"
#include "uthash-master/src/utlist.h"

//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

//------------------------------------------------------------------- 
int synfloodcount = 0;

typedef struct{
	char padding[8];
	u_char sha[6];      /* Sender hardware address */ 
	u_char spa[4];      /* Sender IP address       */
	u_char tha[6];      /* Target hardware address */ 
	u_char tpa[4];      /* Target IP address       */ 
} pkt_info;

pkt_info pkts[3]; // Defined ARP's with corresponding MAC and IP's

	/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	u_char ip_src[4];	/*src address*/
	u_char ip_dst[4]; 	/*dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

void arrayinit(char *sha, char *spa, char q, char w, char e, char r, char t, char y, int a, int b, int c, int d){
	sha[0] = q;
	sha[1] = w;
	sha[2] = e;
	sha[3] = r;
	sha[4] = t;
	sha[5] = y;
	spa[0] = a;
	spa[1] = b;
	spa[2] = c;
	spa[3] = d;
}

int checkspoof(char *sha1, char *sha2, char *spa1, char *spa2){
	int g = 0;
	int j = 0;
	while(g < 4){
		if(spa1[g] != spa2[g]){
			return 0;
		}
		g++;
		if(g == 4){
			while(j < 6){
				if(sha1[j] != sha2[j])
					return -1;
				j++;
			}
		}
	}
	return 0;
}

typedef struct{
	u_char dport;
	UT_hash_handle hh;
	int pktnum;
}key;
	
typedef struct list_{
	u_char ipaddress[4];
	struct list_ *next;
	key *table;
	unsigned int pcount;
}list;

//make sure to pass victim ip as well and add that member to list struct
void listcreate(list **ip, char *ipaddress){
	int g;
	*ip = malloc(sizeof(list));
	for(g = 0; g < 4; g++){
		(*ip)->ipaddress[g] = ipaddress[g];
	}
	(*ip)->table = NULL;
	(*ip)->next = NULL;
	(*ip)->pcount = 0;
}

void keycreate(key **entry, u_char dport, int pktnum){
	*entry = malloc(sizeof(key));
	(*entry)->dport = dport;
	(*entry)->pktnum = pktnum;
}

int equals(list *l1, list *l2){
	int g;
	for(g = 0; g < 4; g++){
		if(l1->ipaddress[g] > l2->ipaddress[g])
			return -1;	
		if(l1->ipaddress[g] < l2->ipaddress[g])
			return 1;
	}
	return 0;
}
list *head = NULL;

int checkportscan(list **ip, key **entry){
	//linked list of ips, hash of their correspoinding syn destination ports, total count for each
	list *temp;
	key *item;
	int pktcount = 0;
	LL_SEARCH(head, temp, *ip, equals);
	if(temp == NULL){
		LL_PREPEND(head, *ip);
	}
	else{
		HASH_FIND_INT(temp->table, &((*entry)->dport), item);
		if(item == NULL){
			temp->pcount++;
			HASH_ADD_INT(temp->table, dport, *entry);
			if(temp->pcount >= 100){
				printf("WARNING PORT SCAN ATTEMPT: PACKET NUMBERS\n");
				while(pktcount < temp->pcount-1){
					printf("MALICIOUS PACKET NUMBER: %d\n",temp->table->pktnum);
					temp->table = (key *)temp->table->hh.next;
					pktcount++;
				}
				temp->pcount = 0;
				return -1;
			}
		}
	}
	return 0;

}

typedef struct timestamp_{
	unsigned long sec;
	unsigned long usec;
	struct timestamp_ *next;
	int pktnum;
}timestamp;

typedef struct portlist_{
	u_char dport;
	timestamp *head;
	struct portlist_ *next;
	int syncount;
}portlist;

void portlistcreate(portlist **new, u_char dport){
	*new = malloc(sizeof(portlist));
	(*new)->dport = dport;
	(*new)->head = NULL;
	(*new)->next = NULL;
	(*new)->syncount = 0;
}

void timestampcreate(timestamp **new, long sec, long usec, int pktnum){
	*new = malloc(sizeof(timestamp));
	(*new)->pktnum = pktnum;
	(*new)->sec = sec;
	(*new)->usec = usec;
	(*new)->next = NULL;
}

portlist *phead = NULL;

int checksynflood(portlist **insert, timestamp **tstamp){
	int listlength = 0;
	timestamp *temp;
	timestamp *iter;
	portlist *ptemp;
	LL_SEARCH_SCALAR(phead, ptemp, dport, (*insert)->dport);
	if(ptemp != NULL){
		if(ptemp->head != NULL){
			if(((*tstamp)->sec - ptemp->head->sec == 0 && (*tstamp)->usec - ptemp->head->usec < 99999) || ((*tstamp)->sec - ptemp->head->sec == 1 && (*tstamp)->usec - ptemp->head->usec == 0)){
				LL_APPEND(ptemp->head, *tstamp);
				ptemp->syncount++;
				if(ptemp->syncount >= 100){
					printf("WARNING: ATTEMPTED SYN FLOOD!\n");
					LL_FOREACH(ptemp->head, iter) printf("MALICIOUS PACKET NUMBER: %d\n", iter->pktnum);
					ptemp->syncount = 0;
					ptemp->head = NULL;;
					return -1;
				}
			}
			else if((*tstamp)->sec - ptemp->head->sec > 0){
				if(ptemp->head->next != NULL){
					ptemp->head = ptemp->head->next;
					temp = ptemp->head;
					while((*tstamp)->sec - temp->sec > 0 || ((*tstamp)->sec - ptemp->head->sec == 1 && (*tstamp)->usec - ptemp->head->usec == 0)){
						if(temp->next == NULL){
							ptemp->syncount = 0;
							ptemp->head = temp;
							LL_APPEND(ptemp->head, *tstamp);
							return 0;
						}
						temp = temp->next;
						listlength++;
					}
					ptemp->head = temp;
					LL_APPEND(ptemp->head, *tstamp);
					ptemp->syncount -= listlength;
					if(ptemp->syncount < 0){
						ptemp->syncount = 0;
					}
				}
				else{
					LL_APPEND(ptemp->head, *tstamp);
				}
			}
			else{
			}
		}
		else{
			LL_PREPEND(ptemp->head, *tstamp);
		}
	}
	else{
		LL_PREPEND(phead, *insert);
		LL_PREPEND((*insert)->head, *tstamp);
	}
	return 0;
}

int main(int argc, char **argv) 
{ 
	arrayinit(pkts[0].sha, pkts[0].spa, '\x7c', '\xd1', '\xc3', '\x94', '\x9e', '\xb8', 192, 168, 0, 100);
	arrayinit(pkts[1].sha, pkts[1].spa, '\xd8', '\x96', '\x95', '\x01', '\xa5', '\xc9', 192, 168, 0, 103);
	arrayinit(pkts[2].sha, pkts[2].spa, '\xf8', '\x1a', '\x67', '\xcd', '\x57', '\x6e', 192, 168, 0, 1);
	unsigned int ip_offset = 14;
	unsigned int arp_count = 0;
	struct bpf_program fp; 
	struct pcap_pkthdr header; 
	const u_char *packet;
	pkt_info *arp;
	struct sniff_tcp *tcp;
	struct sniff_ip *iphdr;
	list *iptemp;
	key *entrytemp;
	portlist *ptemp;
	timestamp *ttemp;
	int g;
	int pktnum = 1;
 
	if (argc != 2) { 
  		fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
 		exit(1); 
  	} 
    	
	pcap_t *handle; 
    	char errbuf[PCAP_ERRBUF_SIZE]; 
    	handle = pcap_open_offline(argv[1], errbuf); 
 
    	if (handle == NULL) { 
      		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
     		 return(2); 
    	} 
    	if(pcap_compile(handle, &fp, (const char *)&"arp or tcp",0 , PCAP_NETMASK_UNKNOWN) == -1){
		printf("%s\n", pcap_geterr(handle));
	} 
    	if(pcap_setfilter(handle, &fp) == -1){
		printf("%s \n", pcap_geterr(handle));
	} 
 
   	while ((packet = pcap_next(handle,&header))) { 
	     	u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data 
      
     		int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
 
      		if (ether_type == ETHER_TYPE_IP){ 
			iphdr = (struct sniff_ip *)(packet+14);
			tcp = (struct sniff_tcp *)(packet+14+(IP_HL(iphdr)*4));
		
			if(tcp->th_flags == TH_SYN){
				listcreate(&iptemp, iphdr->ip_src);
				keycreate(&entrytemp, tcp->th_dport, pktnum);

				if(checkportscan(&iptemp, &entrytemp) == -1){
					printf("WARNING: ATTEMPTED PORT SCAN: OFFENDING IP AND VICTIM IP:\n\t");
					for(g = 0; g<4; g++)
						printf("%d.", iphdr->ip_src[g]);
			        	printf("\t");
					for(g = 0; g<4; g++)
						printf("%d.", iphdr->ip_dst[g]); 
			        	printf("\n");
					arp_count++;
				}

				portlistcreate(&ptemp, tcp->th_dport);
				timestampcreate(&ttemp, header.ts.tv_sec, header.ts.tv_usec, pktnum);

				if(checksynflood(&ptemp, &ttemp) == -1){
					printf("WARNING ATTEMPTED SYN FLOOD: OFFENDING IP AND VICTIM IP\n");
					for(g = 0; g<4; g++)
						printf("%d.", iphdr->ip_src[g]);
			        	printf("\t");
					for(g = 0; g<4; g++)
						printf("%d.", iphdr->ip_dst[g]); 
			        	printf("\n");
					synfloodcount++;	
				}
			}
		}
      		else if(ether_type == 0x0806){
      			arp = (pkt_info *)(packet+ip_offset);
      		
			if(checkspoof(pkts[2].sha, arp->sha, pkts[2].spa, arp->spa) == -1 || checkspoof(pkts[1].sha, arp->sha, pkts[1].spa, arp->spa) == -1 || checkspoof(pkts[0].sha, arp->sha, pkts[0].spa, arp->spa) == -1){ 
				printf("\nWARNING: ATTEMPTED ARP SPOOF! MALICIOUS PACKET NUMBER: %d\n", pktnum);
	     			printf("\t\t\t\tOFFENDING MAC: ");
	     			for(g = 0; g<6; g++)
	     				printf("%02X:", arp->sha[g]);
				printf("\n"); 
			}     	     		
		}

     /* for(g = 0; g<6; g++)
      printf("%02X:", arp->sha[g]); 
      printf("\n"); 
      for(g = 0; g<4; g++)
      printf("%d.", arp->spa[g]); 
      printf("\n");*/
		pktnum++; 
    	} //end internal loop for reading packets (all in one file) 
 
    	pcap_close(handle);  //close the pcap file 
 
  	printf("arpcount: %d\n", arp_count);
	printf("synflood count: %d\n", synfloodcount);

  	return 0; //done
} //end of main() function
