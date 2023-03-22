#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "libnet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

int my_ntoa(uint16_t num){
	return ((num&0xff)<<8)|((num&0xff00)>>8);
}
void print_port(u_int16_t port){
	printf(":%d",my_ntoa(port));
}

void print_ip(u_int8_t *ip){
	int i=0;
	for (i=0;i<3;i++){
		printf("%d.",ip[i]);
	}
	printf("%d",ip[i]);
}

void print_addr(u_int8_t *addr){
	int i=0;
	for(i=0;i<5;i++){
		printf("%02x:",addr[i]);
	}
	printf("%02x",addr[i]);
}


int check_ipv4(struct libnet_ethernet_hdr* eth_header){
	if((my_ntoa((*eth_header).ether_type))== 0x0800) {
		return 1;
	}
	else{
		return 0;
	}
}

int check_tcp(struct libnet_ipv4_hdr* ip_header){
	if((*ip_header).ip_p == 6){
		return 1;
	} 
	else{
		return 0;
	}
}

void Ether_header(struct libnet_ethernet_hdr* eth_header){
	print_addr((*eth_header).ether_shost);
	printf(" -> ");
	print_addr((*eth_header).ether_dhost);
	printf(", ");
}

void IP_port_header(struct libnet_ipv4_hdr* ip_header,struct libnet_tcp_hdr* tcp_header){
	print_ip((*ip_header).ip_src);
	print_port((*tcp_header).th_sport);
	printf(" -> ");
	print_ip((*ip_header).ip_dst);
	print_port((*tcp_header).th_dport);
	printf(", ");
}

void Payload(struct libnet_ipv4_hdr* ip_header,struct libnet_tcp_hdr* tcp_header,const u_char* packet,int caplen){
	int packet_idx=0,distance=0,i=0;
	packet_idx = sizeof(struct libnet_ethernet_hdr) + (*ip_header).ip_hl * 4 + (*tcp_header).th_off * 4; 
	distance = (caplen) - packet_idx;
	if (distance<0){
		printf("error!!");
	}
	else if (distance == 0) {
		printf("-");
	} 
	else{
		for(i=0; i<distance; i++) {
			if (i>=10){
				break;
			}
			printf("%02x|", packet[packet_idx]);
			packet_idx++;
		}
	}
}
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
		}
		//printf("%u bytes captured\n", header->caplen);

		const u_char* tmp_packet;
		tmp_packet = packet;
		struct libnet_ethernet_hdr* eth_header;
		eth_header = (struct libnet_ethernet_hdr*) tmp_packet;
		tmp_packet += sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr* ip_header;
		ip_header = (struct libnet_ipv4_hdr*) tmp_packet;
		tmp_packet += sizeof(struct libnet_ipv4_hdr);
		struct libnet_tcp_hdr* tcp_header;
		tcp_header = (struct libnet_tcp_hdr*)tmp_packet;
		tmp_packet += sizeof(struct libnet_tcp_hdr*);

		if (check_tcp(ip_header)&&check_ipv4(eth_header)){
			Ether_header(eth_header);
			IP_port_header(ip_header,tcp_header);
			Payload(ip_header,tcp_header,packet,(*header).caplen);
			printf("\n============================================\n");
		}
	}

	pcap_close(pcap);
}
