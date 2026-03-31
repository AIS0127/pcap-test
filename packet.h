#include<stdint.h>

#define IPV4 0x0800
#define IPV6 0x86DD

#define TCP 6


// | dest_mac (6) | src_mac (6) | ethertype (2) |
typedef struct  __attribute__((packed)) ethernet_header_t {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;


typedef struct __attribute__((packed)) ipv4_header_t {
    uint8_t ver_ihl; // version(4) | ihl (4)
    uint8_t tos; 
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment; // flags(3) | fragment (13)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} ipv4_header_t;

typedef struct __attribute__((packed)) ipv6_header_t {
    uint32_t ver_tc_flow;   // Version(4) + Traffic Class(8) + Flow Label(20)
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_ip[16];
    uint8_t dest_ip[16];
} ipv6_header_t;


typedef struct __attribute__((packed)) tcp_header_t {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t offset_flags;
    uint16_t window;
    uint16_t checksnum;
    uint16_t urgent_pointer;
} tcp_header_t;