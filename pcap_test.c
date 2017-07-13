#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "net_header.h"

void print_packet(const u_char *packet, const DWORD total_size) {
    for(unsigned int i=0; i<0x20; i++) {
	printf("[%03x] ", i*16);
	for(unsigned int j=0; j<16; j++)
	    printf("%02x ", (*((char*)packet+((i*16)+j))&0xff));
	printf("\n");
    }
}

int get_headers(pether_h peh, pip_h pih, ptcp_h pth, const u_char *packet) {
    memcpy(peh, packet, ETHERNET_SIZE);
    if(peh->Type == TYPE_IP) {
	memcpy(pih, packet+ETHERNET_SIZE, IP_MIN_SIZE);
	if(ip_h_len(pih->Ver_Len) != IP_MIN_SIZE)
	    memcpy(pih, packet+ETHERNET_SIZE, ip_h_len(pih->Ver_Len));
	if(pih->Protocol == TCP_PROTOCOL) {
	    memcpy(pth, packet+ETHERNET_SIZE+ip_h_len(pih->Ver_Len), TCP_SIZE);
	}
    }
}

void print_ether(const pether_h peh) {
    for(unsigned int i=0; i<6; i++) {
	printf("%02x", peh->Source[i]&0xff);
	if(i==5) break;
	printf(":");
    }
    printf("\n");
}

void print_ip(const pip_h pih) {
    for(unsigned int i=0; i<4; i++) {
	printf("%u", *((char*)&(pih->Source)+i)&0xff);
	if(i==3) break;
	printf(".");
    }
    printf("\n");
    printf("ip header len : %d\n", ip_h_len(pih->Ver_Len));
}

void print_tcp(const ptcp_h pth) {
    printf("source port : %u\n", ntohs(pth->Source&0xffff));
    printf("dest port : %u\n", ntohs(pth->Dest&0xffff));
}

