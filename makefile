all:eth_txt eth_size eth_mac eth_time eth_type ip_txt \
	ip_addr ip_ttl ip_protocal arp icmp ip_dns tcp_protocal \
	tcp_tcp

eth_txt:eth_txt.c
	gcc -g -lpcap eth_txt.c  -oeth_txt 

eth_size:eth_size.c
	gcc -g -lpcap eth_size.c -oeth_size

eth_mac:eth_mac.c
	gcc -g -lpcap eth_mac.c -oeth_mac

eth_time:eth_time.c
	gcc -g -lpcap eth_time.c -oeth_time

eth_type:eth_type.c
	gcc -g -lpcap eth_type.c -oeth_type

ip_txt:ip_txt.c
	gcc -g -lpcap ip_txt.c -oip_txt

ip_addr:ip_addr.c
	gcc -g -lpcap ip_addr.c -oip_addr

ip_ttl:ip_ttl.c
	gcc -g -lpcap ip_ttl.c -oip_ttl

ip_protocal:ip_protocal.c
	gcc -g -lpcap ip_protocal.c -oip_protocal

arp:arp.c
	gcc -g -lpcap arp.c -oarp

icmp:icmp.c
	gcc -g  -lpcap  icmp.c -oicmp

ip_dns:ip_dns.c
	gcc -g -lpcap ip_dns.c -oip_dns

tcp_protocal: tcp_protocal.c
	gcc -g -lpcap tcp_protocal.c -otcp_protocal

tcp_tcp:tcp_tcp.c
	gcc -g -lpcap tcp_tcp.c -otcp_tcp











