
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/protocols.h>


#include <pcap.h>
#include <netdb.h>


#define DEFAULT_SNAPLEN 68
#define MAXSTRINGSIZE 256
#define MAXENTRY 1024

struct {
	unsigned long int ipaddr;
	char hostname[MAXSTRINGSIZE];
} nametable[MAXENTRY];

int tbllength=0;


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


void intohost(unsigned long int iaddr,char* hn){
	int i;
	extern int tbllength;
	for ( i = 0; i < tbllength; ++i){
		if (nametable[i].ipaddr==iaddr){
			break;
		}
	}

	if (i<tbllength)
	{
		strcpy(hn,nametable[i].hostname);
		//nametable[i].ipaddr=iaddr;
	}else{
		fprintf(stderr, "Internal Error on void intohost()\n");
		exit(0);
	}
}


void reghost(unsigned long int iaddr){
	int i;
	struct hostent *shostname;
	extern int tbllength;
	for (i = 0; i < tbllength; ++i)
	{
		if(nametable[i].ipaddr==iaddr) break;
	}

	if (i==tbllength)
	{
		nametable[i].ipaddr=iaddr;
		shostname=gethostbyaddr((char*)&iaddr,sizeof(iaddr),AF_INET);
		if (shostname!=NULL){
			strcpy(nametable[i].hostname,shostname->h_name);
		}else{
			strcpy(nametable[i].hostname,"");
		}
		tbllength++;
	}
}

void print_hostname(u_char *ipaddr){
	int i;
	unsigned long int iaddr;
	struct hostent *hostname;
	char hn[MAXSTRINGSIZE];

	iaddr=*((unsigned long int*)(ipaddr));

	reghost(iaddr);

	intohost(iaddr,hn);

	if(strlen(hn)>0){
		printf("%s", hn);
	}else{
		for (i = 0; i < 3; ++i)
		{
			printf("%d:", ipaddr[i]);
		}
		printf("%d", ipaddr[i]);
	}

}

void getportname(int portn,char portch[],char* protocal){
	if (getservbyport(htons(portn),protocal)!=NULL)
	{
		strcpy(portch,getservbyport(htons(portn),protocal)->s_name);
	}else{
		sprintf(portch,"%d",portn);
	}
}



void packet_print(u_char *user,const struct pcap_pkthdr *h,const u_char *p){
	
	struct ether_header *eth;
	int i;
	struct ip *iph;
	struct ether_arp *arppkt;
	unsigned int typeno;
	struct icmphdr* icmp;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int datalen=0;
	char* data=NULL;
	u_short srcport,dstport;
	char protocal[MAXSTRINGSIZE];
	char srcp[MAXSTRINGSIZE],dstp[MAXSTRINGSIZE];
	char layer3data[MAXSTRINGSIZE];

	eth=(struct ether_header*)p;
	typeno=ntohs(eth->ether_type);

	if (typeno==ETHERTYPE_IP){
		
		iph=(struct ip *)(p+sizeof(struct ether_header));
 		
 		if (iph->ip_p==IP_TCP)
 		{
 			strcpy(protocal,"tcp");
 			tcph=(struct tcphdr*)(p+sizeof(struct ether_header)+4*iph->ip_hl);
 			srcport=ntohs(tcph->source);
 			dstport=ntohs(tcph->dest);

 			data=(u_char*)(p+sizeof( struct ether_header)+4*iph->ip_hl+4*tcph->doff);
 			datalen=h->len-sizeof(struct ether_header)-4*iph->ip_hl-4*tcph->doff;


 		}else if (iph->ip_p==IP_UDP){
 			strcpy(protocal,"udp");
 			udph=(struct udphdr*)(p+sizeof(struct ether_header)+4*iph->ip_hl);
 			srcport=ntohs(udph->source);
 			dstport=ntohs(udph->dest);

 			data=(u_char*)(p+sizeof( struct ether_header)+4*iph->ip_hl+8);
 			datalen=h->len-sizeof(struct ether_header)-4*iph->ip_hl-8;

 		}else{
 			strcpy(protocal,"---");
 			srcport=dstport=0;
 		}

 		getportname(srcport,srcp,protocal);
 		getportname(dstport,dstp,protocal);

 		print_hostname((u_char*)&(iph->ip_src));
 		printf("(%s:%s)",protocal,srcp);
		
 		
 		print_hostname((u_char*)&(iph->ip_dst));
		printf("(%s:%s)",protocal,dstp);

		
		memset(layer3data,0,sizeof(layer3data));

		for (i = 0; i < MAXSTRINGSIZE-1; ++i)
		{
			if (i>=datalen)
			{
				break;
			}else{
				layer3data[i]=data[i];
			}
		}
		printf("\t%d\t data:%s\n",h->len,layer3data);
		printf("\n");
		fflush(stdout);

	}else if(typeno==ETHERTYPE_ARP || typeno==ETHERTYPE_REVARP){
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

