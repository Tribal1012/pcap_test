#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "net_header.h"


int main(int argc, char *argv[])
{
	ether_h eh;			/* Ethernet header */
	ip_h ih;			/* IP header */
	tcp_h th;			/* TCP header */
	DWORD data_offset = 0;	    	/* for Packet's data */
	DWORD data_len;			/* Packet's data length */

	pcap_t *handle;			/* Session handle */
	DWORD res;
	BYTE *dev;			/* The device to sniff on */
	BYTE errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	BYTE filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	if(argc!=2) {
	    fprintf(stderr, "Usage : %s [device_name]\n", argv[0]);
	    return(2);
	}
	dev = argv[1];

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
		data_offset = get_headers(&eh, &ih, &th, packet);
		
		print_ether(&eh);
		if(eh.Type == TYPE_IP) {
		    print_ip(&ih);
		    if(ih.Protocol == TCP_PROTOCOL) {
			print_tcp(&th);
			data_len = data_len(&ih, &th);
			if(data_len != 0) print_data(((char*)packet)+data_offset, data_len);
		    }
		}
		break;
	    }
	}
	/* And close the session */
	pcap_close(handle);
	    
	return(0);
}
