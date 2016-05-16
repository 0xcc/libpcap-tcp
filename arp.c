
#include <stdio.h>
#include <sys/time.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#define DEFAULT_SNAPLEN 68



void print_mac(u_char *hwadd){
	int i=0;
	for (i = 0; i < 5; ++i){
		printf("%2x:", hwadd[i]);
	}
	printf("%2x", hwadd[i]);
}


void print_ip_addr(u_char *ipaddr){
	int i=0;
	for (i = 0; i < 3; ++i)
	{
		printf("%d.", ipaddr[i]);
	}
	printf("%d", ipaddr[i]);
}

void packet_print(u_char *user,const struct pcap_pkthdr *h,const u_char *p){
	
	struct ether_header *eth;
	int i;
	struct ip *iph;
	struct ether_arp *arppkt;
	unsigned int typeno;
	eth=(struct ether_header*)p;
	typeno=ntohs(eth->ether_type);
/*

	if (ntohs(eth->ether_type)==ETHERTYPE_IP)
	{
		iph=(struct ip *)(p+sizeof(struct ether_header));
		
		print_ip_addr((u_char*)&(iph->ip_src));
		printf("-->");
		print_ip_addr((u_char*)&(iph->ip_dst));

		printf("\t ttl:%d\t protocal:%d", iph->ip_ttl,iph->ip_p);


		printf("\n");
		fflush(stdout);
	}
	*/
	if (typeno==ETHERTYPE_ARP || typeno==ETHERTYPE_REVARP){
		arppkt=(struct ether_arp*)(p+sizeof(struct ether_header));
		if (typeno==ETHERTYPE_ARP){
			printf("ARP ");
		}else{
			printf("RARP ");
		}

		print_mac((u_char*)&(arppkt->arp_sha));
		printf(",");
		print_ip_addr((u_char*)&(arppkt->arp_spa));
		printf("-->");
		print_mac((u_char*)&(arppkt->arp_tha));
		printf(",");
		print_ip_addr((u_char*)&(arppkt->arp_tpa));
		printf("\n");
		fflush(stdout);
	}
}

int  main(int argc, char const *argv[])
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
	if (argc<=1){
		printf("usage :%s <network interface>\n", argv[0]);
		return 0;
	}

	if ((pd=pcap_open_live(argv[1],DEFAULT_SNAPLEN,1,1000,ebuf))==NULL)
	{
		(void)fprintf(stderr, "1:%s\n", ebuf);
	}

	if (pcap_loop(pd,-1,packet_print,NULL)<0)
	{
		(void)fprintf(stderr, "2:pcap_loop: %s\n", pcap_geterr(pd));
	}

	pcap_close(pd);


	return 0;
}

