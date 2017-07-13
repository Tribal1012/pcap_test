typedef char BYTE
typedef short WORD
typedef int DWORD

/*
    L2 Ethernet header
*/
typedef struct _ETHERNET_HEADER {
    BYTE    Dest[6];
    BYTE    Source[6];
    WORD    Length;
} ether_h, *pether_h;


/*
    L3 IP header
*/
#define ip_ver(x) (x>>4)
#define ip_h_len(x) (x&0xf)
#define ip_flags(x) (x>>13)
#define ip_frag(x) (x&&0x1fff)
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
    DWORD   Dest;;	    /* Destination Address */
    union   pad {
	char options[40];
	char pad[40];
    };
} ip_h, *pip_h;


/*
    L4 TCP header
*/
#define tcp_h_len(x)	x
#define tcp_code(x)	(x&3f)
typedef struct _TCP_HEADER {
    WORD    Source;
    WORD    Dest;
    DWORD   Seq_num;	    /* Sequence Number */
    DWORD   Ack_num;	    /* Acknowledgment Number */
    WORD    Len_Rsv_Code;   /* Header Length & Reserved & Code Bit */
    WORD    Window;	    /* Window */
    WORD    Checksum;	    /* Checksum */
    WORD    Urgent;	    /* Urgent */
} tcp_h, *ptcp_h;
