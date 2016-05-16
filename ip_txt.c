
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

void packet_print(u_char *user,const struct pcap_pkthdr *h,const u_char *p){
	
	struct ether_header *eth;
	int i;
	struct ip *iph;
	eth=(struct ether_header*)p;


	if (ntohs(eth->ether_type)==ETHERTYPE_IP)
	{
		iph=(struct ip *)(p+sizeof(struct ether_header));
		printf("%s\n", "Find IP datagram");
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

