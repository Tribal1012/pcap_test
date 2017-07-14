#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "net_header.h"

int main(int argc, char *argv[])
{
	ether_h eh;			/* Ethernet header */
	ip_h ih;			/* IP header */
	tcp_h th;			/* TCP header */

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

	/*
	   get & print 
	   ethernet header + ip header + tcp header 
	 */
	memset(&eh, 0, sizeof(eh));
	memset(&ih, 0, sizeof(ih));
	memset(&th, 0, sizeof(th));
	while(1) {
	    if(pcap_next_ex(handle, &header, &packet)) {
		get_headers(&eh, &ih, &th, packet);
		
		print_packet(packet, ih.Total_len*4);
		print_ether(&eh);
		if(eh.Type == TYPE_IP) {
		    print_ip(&ih);
		    if(ih.Protocol == TCP_PROTOCOL) {
			print_tcp(&th);
		    }
		}
		break;
	    }
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
