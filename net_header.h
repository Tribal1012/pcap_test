#ifndef __NET_HEADER_H__
#define __NET_HEADER_H__

typedef unsigned char	BYTE;
typedef unsigned short	WORD;
typedef unsigned int	DWORD;

/*
    L2 Ethernet header
*/
#define TYPE_IP 0x8
#define ETHERNET_SIZE sizeof(ether_h)
typedef struct _ETHERNET_HEADER {
    BYTE    Dest[6];
    BYTE    Source[6];
    WORD    Type;
} ether_h, *pether_h;


/*
    L3 IP header
*/
#define IP_MIN_SIZE 0x14
#define TCP_PROTOCOL 0x6
#define UDP_PROTOCOL 0x11
#define IPV6_PROTOCOL 0x29

#define ip_ver(x) (((pip_h)x)>>4)
#define ip_h_len(x) (((pip_h)x)->Ver_Len&0xf)*4
#define ip_t_len(x) (((pip_h)x)->Total_len)*4
#define ip_flags(x) (((pip_h)x)>>13)
#define ip_frag(x) (((pip_h)x)->&&0x1fff)
typedef struct _IP_HEADER {
    BYTE    Ver_Len;	    /* Version & Header Length */
    BYTE    Service_type;   /* Service_Type */
    WORD    Total_len;	    /* Total_Length */
    WORD    Identification; /* Identification */
    WORD    Flag_Frag;	    /* flags & fragmentation offset */
    BYTE    TTL;	    /* TTL */
    BYTE    Protocol;	    /* Protocol(tcp & udp) */
    WORD    Checksum;	    /* Header Checksum */
    DWORD   Source;	    /* Source Address */
    DWORD   Dest;	    /* Destination Address */
    union   _ip_pad {
	char options[40];
	char pad[40];
    } ip_pad;
} ip_h, *pip_h;


/*
    L4 TCP header
*/
#define TCP_MIN_SIZE	0x14
#define TCP_SIZE	sizeof(tcp_h)

#define tcp_h_len(x)	(((ptcp_h)x)->Len_Rsv_Code>>12)*4
#define tcp_code(x)	(((ptcp_h)x)->Len_Rsv_Code&0x3f)
typedef struct _TCP_HEADER {
    WORD    Source;
    WORD    Dest;
    DWORD   Seq_num;	    /* Sequence Number */
    DWORD   Ack_num;	    /* Acknowledgment Number */
    WORD    Len_Rsv_Code;   /* Header Length & Reserved & Code Bit */
    WORD    Window;	    /* Window */
    WORD    Checksum;	    /* Checksum */
    WORD    Urgent;	    /* Urgent */
    union   _tcp_pad {
	char options[40];
	char pad[40];
    } tcp_pad;
} tcp_h, *ptcp_h;

int get_headers(pether_h peh, pip_h pih, ptcp_h pth, const u_char *packet);
void print_ether(const pether_h peh);
void print_ip(const pip_h pih);
void print_tcp(const ptcp_h pth);
//void print_packet(const u_char *packet, const DWORD total_size);

#endif
