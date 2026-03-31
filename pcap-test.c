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
	printf(" |                                            | \n");
}

void print_ip_tcp_header(const u_char *packet){
	ipv4_header_t *ipv4_header = (ipv4_header_t *)&packet[sizeof(ethernet_header_t)];
	uint8_t* src = (uint8_t*)(&ipv4_header->src_ip);
	uint8_t* dest = (uint8_t*)(&ipv4_header->dest_ip);
	uint32_t ip_header_len = (ipv4_header->ver_ihl & 0x0F) * 4;
	tcp_header_t *tcp_header = (tcp_header_t *)&packet[sizeof(ethernet_header_t) + ip_header_len];
	const uint8_t *offset_flags = (const uint8_t *)&tcp_header->offset_flags;
	uint32_t tcp_header_len = (offset_flags[0] >> 4) * 4;
	uint32_t data_len = ntohs(ipv4_header->total_length) - ip_header_len - tcp_header_len;
	uint8_t *data = (uint8_t *)tcp_header + tcp_header_len;

	printf("[+]============== IPV4 Header ===============[+]\n");
	printf("[Src] : %u.%u.%u.%u\n",src[0],src[1],src[2],src[3]);
	printf("[Dest] : %u.%u.%u.%u\n",dest[0],dest[1],dest[2],dest[3]);
	printf("[+]==========================================[+]\n");
	printf(" |                                            |\n");
	printf("[+]=============== TCP Header ===============[+]\n");
	printf("[Src] : %hu\n", ntohs(tcp_header->src_port));
	printf("[Dest] : %hu\n", ntohs(tcp_header->dest_port));
	printf("[Length] : %u\n", data_len);
	printf("[Data] : \n");
	size_t print_len = data_len < 20 ? data_len : 20;
	for(size_t i = 0; i < print_len; i++){
		if(i % 5 == 0) printf("%9s", "");
		printf("%02X ", data[i]);
		if(i % 5 == 4 || i + 1 == print_len) printf("\n");
	}
	printf("[+]==========================================[+]\n\n");

}

void print_each_header(const u_char * packet){
	print_eth_header((ethernet_header_t*)packet);
	print_ip_tcp_header(packet);
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
