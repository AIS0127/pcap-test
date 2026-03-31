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

	if(eth_header->ethertype == IPV4){
		return ((ipv4_header_t *)(&packet[sizeof(ethernet_header_t)]))->protocol == TCP;
	}else if(eth_header->ethertype == IPV6){
		return ((ipv6_header_t *)(&packet[sizeof(ethernet_header_t)]))->next_header == TCP;
	}else{
		return -1;
	}
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
			printf("it's TCP !\n");
		}
		
	}

	pcap_close(pcap);
}

