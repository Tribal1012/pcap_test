#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "net_header.h"

void print_packet(const u_char *packet) {
    for(unsigned int i=0; i<0x20; i++) {
	printf("[%03x] ", i*16);
	for(unsigned int j=0; j<16; j++)
	    printf("%02x ", (*((char*)packet+((i*16)+j))&0xff));
	printf("\n");
    }
}

int main(int argc, char *argv[])
{
	ether_h eh;
	ip_h ih;
	tcp_h th;

	pcap_t *handle;			/* Session handle */
	int res;
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	memset(&eh, 0, sizeof(eh));
	memset(&ih, 0, sizeof(ih));
	memset(&th, 0, sizeof(th));
	while(1) {
	    if(pcap_next_ex(handle, &header, &packet)) {
		memcpy(&eh, packet, sizeof(eh));
		for(unsigned int i=0; i<6; i++) {
		    printf("%02x", eh.Source[i]&0xff);
		    if(i==5) break;
		    printf(":");
		}
		printf("\n");
		if(eh.Type == 0x8) {
		    memcpy(&ih, packet+sizeof(eh), IP_MIN_SIZE);
		    for(unsigned int i=0; i<4; i++) {
			printf("%u", (char)((char*)&ih.Source)[i]&0xff);
			if(i==3) break;
			printf(".");
		    }
		    printf("\n");
		    if(ip_h_len(ih.Ver_Len) != IP_MIN_SIZE)
			memcpy(&ih, packet+sizeof(eh), ip_h_len(ih.Ver_Len));
		    if(ih.Protocol == 0x6) {
			memcpy(&th, packet+sizeof(eh)+ip_h_len(ih.Ver_Len), 
				sizeof(th));
			printf("port : %u\n", th.Dest&0xffff);
		    }
		}
		print_packet(packet);
		break;
	    }
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
