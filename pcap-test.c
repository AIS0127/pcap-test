#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "packet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int is_eligible(const u_char * packet){
	ethernet_header_t *eth_header = (ethernet_header_t *)packet;

	uint16_t ip_version = ntohs(eth_header->ethertype);
	if(ip_version == IPV4){
		return ((ipv4_header_t *)(&packet[sizeof(ethernet_header_t)]))->protocol == TCP;
	} else{
		return 0;
	}
}
void print_eth_header(ethernet_header_t *eth_header){
	printf("[+]============ Ethernet Header =============[+]\n");
	printf("[Src] : %02X:%02X:%02X:%02X:%02X:%02X\n",eth_header->src_mac[0],eth_header->src_mac[1],eth_header->src_mac[2],eth_header->src_mac[3],eth_header->src_mac[4],eth_header->src_mac[5]);
	printf("[Dest] : %02X:%02X:%02X:%02X:%02X:%02X\n",eth_header->dest_mac[0],eth_header->dest_mac[1],eth_header->dest_mac[2],eth_header->dest_mac[3],eth_header->dest_mac[4],eth_header->dest_mac[5]);
	printf("[+]==========================================[+]\n");
}
void print_ipv4_header(ipv4_header_t *ipv4_header){
	uint8_t* src, *dest;
	
	src = (uint8_t*)(&ipv4_header->src_ip);
	dest = (uint8_t*)(&ipv4_header->dst_ip);

	printf("[+]============== IPV4 Header ===============[+]\n");
	printf("[Src] : %u.%u.%u.%u\n",src[0],src[1],src[2],src[3]);
	printf("[Dest] : %u.%u.%u.%u\n",dest[0],dest[1],dest[2],dest[3]);
	printf("[+]==========================================[+]\n");
}


void print_each_header(const u_char * packet){
	print_eth_header((ethernet_header_t*)packet);
	printf("\n");
	print_ipv4_header((ipv4_header_t*)&packet[sizeof(ethernet_header_t)]);
	printf("\n");
}


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}else if(is_eligible(packet)){
				print_each_header(packet);	
		}
		
	}

	pcap_close(pcap);
}

