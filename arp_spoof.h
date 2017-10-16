#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#define IP_ADDR_LEN 4
#define MAX_THREAD 5

struct arp_header {
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t ar_sha[6];
	u_int8_t ar_sip[4];
	u_int8_t ar_tha[6];
	u_int8_t ar_tip[4];
};

struct pthread_arg {
	u_int32_t session_num;
	pcap_t *handle;
	u_int8_t *interface;
	u_int8_t attacker_mac[ETHER_ADDR_LEN];
	u_int8_t attacker_ip[IP_ADDR_LEN];
	u_int8_t sender_mac[ETHER_ADDR_LEN];
	u_int8_t sender_ip[IP_ADDR_LEN];
	u_int8_t target_mac[ETHER_ADDR_LEN];
	u_int8_t target_ip[IP_ADDR_LEN];
};

void get_mac(u_int8_t *mac_addr, u_int8_t *interface);
void get_ip(u_int8_t *ip_addr, u_int8_t *interface);
void print_mac(u_int8_t *mac_addr, u_int8_t *name);
void print_ip(u_int8_t *ip_addr, u_int8_t *name);
void gen_arp_packet(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode);
void *arp_spoof(void *data);
void *relay(void *data);
