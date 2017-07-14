#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "net_header.h"

#define COUNT1(x) x/16
#define COUNT2(x) x%16
void print_packet(const u_char *packet, const DWORD total_size) {
    unsigned int i=0;
    unsigned int j=0;

    for(i=0; i<COUNT1(total_size); i++) {
	printf("[%03x] ", i*16);
	for(j=0; j<16; j++)
	    printf("%02x ", (*((char*)packet+((i*16)+j))&0xff));
	printf("\n");
    }
    if(COUNT2(total_size) > 0) {
	printf("[%03x] ", i*16);
	for(j=0; j<COUNT2(total_size); j++)
	    printf("%02x ", (*((char*)packet+((i*16)+j))&0xff));
	printf("\n\n");
    }
}

#define l_endian16(x) ntohs(x & 0xffff)
#define l_endian32(x) ntohl(x & 0xffffffff)
int get_headers(pether_h peh, pip_h pih, ptcp_h pth, const u_char *packet) {
    char* temp[1024] = {0, };

    /* Get a Ethernet Header */
    memcpy(peh, packet, ETHERNET_SIZE);

    /* Get a IP Header */
    if(peh->Type == TYPE_IP) {
	memcpy(temp, packet+ETHERNET_SIZE, IP_MIN_SIZE);
	memcpy(pih, temp, ip_h_len(temp));
	pih->Total_len = l_endian16(((pip_h)temp)->Total_len);
	pih->Identification = l_endian16(((pip_h)temp)->Identification);
	pih->Flag_Frag = l_endian16(((pip_h)temp)->Flag_Frag);
	memset(temp, 0, sizeof(temp));

	/* Get a TCP Header */
	if(pih->Protocol == TCP_PROTOCOL) {
	    memcpy(temp, packet+ETHERNET_SIZE+ip_h_len(pih), TCP_MIN_SIZE);
	    memcpy(pth, temp, tcp_h_len(temp));
	    
	    pth->Source = l_endian16(((ptcp_h)temp)->Source);
	    pth->Dest = l_endian16(((ptcp_h)temp)->Dest);
	    pth->Seq_num = l_endian32(((ptcp_h)temp)->Seq_num);
	    pth->Ack_num = l_endian32(((ptcp_h)temp)->Ack_num);

	    memcpy(&pth->data, packet+ETHERNET_SIZE+ip_h_len(pih)+tcp_h_len(temp), 24);
	}
    }
}

void print_ether(const pether_h peh) {
    puts("==========================================");
    puts("|           Ethernet Header              |"); 
    puts("==========================================");
    printf("MAC Destination Address : ");
    for(unsigned int i=0; i<6; i++) {
	printf("%02x", peh->Dest[i]&0xff);
	if(i==5) break;
	printf(":");
    }
    printf("\n");
    
    printf("MAC Source Address      : ");
    for(unsigned int i=0; i<6; i++) {
	printf("%02x", peh->Source[i]&0xff);
	if(i==5) break;
	printf(":");
    }
    printf("\n");
}

void print_ip(const pip_h pih) {
    puts("==========================================");
    puts("|		  IP Header                |"); 
    puts("==========================================");
    printf("IP Source Address      : ");
    for(unsigned int i=0; i<4; i++) {
	printf("%u", *((char*)&(pih->Source)+i)&0xff);
	if(i==3) break;
	printf(".");
    }
    printf("\n");

    printf("IP Destination Address : ");
    for(unsigned int i=0; i<4; i++) {
	printf("%u", *((char*)&(pih->Dest)+i)&0xff);
	if(i==3) break;
	printf(".");
    }
    printf("\n");
}

void print_tcp(const ptcp_h pth) {
    puts("==========================================");
    puts("|		 TCP Header                |"); 
    puts("==========================================");
    printf("Source port     : %u\n", pth->Source);
    printf("Destnation port : %u\n", pth->Dest);

    printf("Data[24 Bytes]  : ");
    for(unsigned int i=0; i<24; i++) {
	printf("%c", isprint(*(pth->data+i))?(char)*(pth->data+i):'.');
    }
    printf("\n");
}

