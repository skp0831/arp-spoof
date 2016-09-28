#include <winsock2.h>
#include <iostream>
#include <windows.h>   
using namespace std;
#include <stdio.h>
#include <stdint.h>
#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#include <iphlpapi.h>
#pragma comment(lib,"wpcap.lib")


// for GetAdaptersInfo()

#pragma comment(lib, "iphlpapi.lib" )

#define MAC_ADDR_LEN    6
#define IP_ADDR_LEN    4

//	�Լ�
typedef struct _ethernet_HEADER		//ethernet ��� ����ü

{

	u_int8_t dest_mac[MAC_ADDR_LEN];	/* destination ethernet address */

	u_int8_t src_mac[MAC_ADDR_LEN];		/* source ethernet address */

	u_int16_t ethernet_protocol;		/* protocol */

}ethernet_HEADER, *Pethernet_HEADER;

typedef struct _IP_HEADER		//IP ��� ����ü

{
	u_int8_t	ip_headerlengthversion;      /* header length + version */

	u_int8_t	ip_typeofservice;       /* type of service */

	u_int16_t	ip_totallenng;         /* total length */
	u_int16_t	ip_identification;          /* identification */
	u_int16_t	ip_flags;	// Flags (3 bits) + Fragment offset (13 bits)
#define DONT_FRAG(frag)   (frag & 0x40)

#define MORE_FRAG(frag)   (frag & 0x20)

#define FRAG_OFFSET(frag) (ntohs(frag) & (~0x6000))

	u_int8_t ip_timetolive;          /* time to live */
	u_int8_t ip_protocol;            /* protocol */
	u_int16_t ip_checksumsum;         /* checksum */

	UINT	src_ip;			// Source address
	UINT	dest_ip;			// Destination address

	UINT		op_pad;			// Option + Padding

}IP_HEADER, *PIP_HEADER;

typedef struct _ARP_HEADER		//ARP �������ü
{
	u_int16_t arp_hardware;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
	u_int16_t arp_protocol;         /* format of protocol address */
	u_int8_t  arp_hardwarelength;         /* length of hardware address */
	u_int8_t  arp_protocollength;         /* length of protocol addres */
	u_int16_t arp_opertaion;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
	u_int8_t src_mac[MAC_ADDR_LEN];		/* source arp address */
	UINT	src_ip;		// Source address
	u_int8_t dest_mac[MAC_ADDR_LEN];	/* destination arp address */
	UINT	dest_ip;		// Destination address

							/* address information allocated dynamically */
}ARP_HEADER, *PARP_HEADER;



//	�Լ�
void arp_request();		//arp-request
void getmyinfo();		//MY MAC,IP���� ã��
BOOL initpcap();		// initpcap() - ĸó ��ġ �ʱ�ȭ

						//	���� ����

pcap_t				*adhandle;
struct pcap_pkthdr	*header;
const u_char		*pkt;
u_char	info;
u_int8_t mymac[6];
u_long myip;
u_long victimip;


int main()

{

	if (initpcap() == FALSE)	return 1;		//ĸó ��ġ �ʱ�ȭ
	printf("����������������������������� ��PC���� ����\n");

	getmyinfo();		//MY MAC,IP���� ã��
	arp_request();		//arp-request


	return 0;

}






BOOL initpcap()		//ĸó ��ġ ã�� �� �ʱ�ȭ

{

	pcap_if_t *alldevs;		//��ġ ����

	char errbuf[256];		//����

	bpf_u_int32 NetMask;

	struct bpf_program fcode;

	pcap_if_t *d;




	// PCAP �ʱ�ȭ

	printf("!] PCAP�� �ʱ�ȭ ���Դϴ�... \n");



	if (pcap_findalldevs(&alldevs, errbuf) == -1)		//��ġ ��� �˻�

	{

		printf("?] pcap_findalldevs ���� ���� �߻� \n");

		return FALSE;

	}



	for (d = alldevs; d->next != NULL; d = d->next);		// ��ġ�� ã���� ���� �˻�



	printf("!] ��Ʈ��ũ ī�� �� [ %s ] \n", d->description);		// ��Ʈ��ũ ī��� ���




															// ��ġ ����

	if ((adhandle = pcap_open_live(d->name,	// ��ġ ��

		65536,									// ��Ŷ�� ���� ������

		0,										// promiscuous mode

		0,										// read timeout

		errbuf									// ���� ����

	)) == NULL)

	{

		printf("?] [ %s ] �� winpcap���� �������� �ʽ��ϴ�.\n", d->name);

		pcap_freealldevs(alldevs);	// ��ġ ��� ����

		return FALSE;

	}




	pcap_freealldevs(alldevs);




	NetMask = 0xffffff;




	// ���͸����� ������

	if (pcap_compile(adhandle, &fcode, "tcp or udp", 1, NetMask) < 0)

	{

		printf("?] pcap_compile���� ���� �߻� \n");

		return FALSE;

	}




	// ���� set

	if (pcap_setfilter(adhandle, &fcode)<0)

	{

		printf("?] pcap_setfilter���� ���� �߻� \n");

		return FALSE;

	}




	printf("!] PCAP �ʱ�ȭ �Ϸ�... \n");

	return TRUE;

}



void getmyinfo() {

	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);
	int result = GetAdaptersInfo(Info, &size);        // MAC address ��������
	if (result == ERROR_BUFFER_OVERFLOW)    //  �޸𸮰� �����ϸ� �� �Ҵ��ϰ� ��ȣ��

	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}


	myip = inet_addr(Info->IpAddressList.IpAddress.String);

	mymac[0] = Info->Address[0];
	mymac[1] = Info->Address[1];
	mymac[2] = Info->Address[2];
	mymac[3] = Info->Address[3];
	mymac[4] = Info->Address[4];
	mymac[5] = Info->Address[5];

	printf("IP address : %s\n", Info->IpAddressList.IpAddress.String);
	printf("MAC address : %0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X\n",

		mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
};

void arp_request()
{


	printf("victim�� IP�� �Է��Ͻÿ�\n");		//victim ip�ּ� �Է�
	char getip[15];
	gets_s(getip, sizeof(getip));
	victimip = inet_addr(getip);
	printf("%0x �� �Է¹޾ҽ��ϴ�\n", victimip);



	u_char packetdata[2048];
	Pethernet_HEADER eh = (Pethernet_HEADER)((UCHAR *)packetdata);
	PARP_HEADER ah = (PARP_HEADER)((UCHAR *)packetdata + 14);


	eh->dest_mac[0] = 0xff; //arp req�̹Ƿ� ��ε�ĳ�������� ���
	eh->dest_mac[1] = 0xff;
	eh->dest_mac[2] = 0xff;
	eh->dest_mac[3] = 0xff;
	eh->dest_mac[4] = 0xff;
	eh->dest_mac[5] = 0xff;

	eh->src_mac[0] = mymac[0];  //  ���ּ�
	eh->src_mac[1] = mymac[1];
	eh->src_mac[2] = mymac[2];
	eh->src_mac[3] = mymac[3];
	eh->src_mac[4] = mymac[4];
	eh->src_mac[5] = mymac[5];

	eh->ethernet_protocol = htons(0x0806); //0x0806 �̴��� ������ ������ 

	ah->arp_hardware = htons(0x0001); //�̴���  : 0x0001
	ah->arp_protocol = htons(0x0800);       // type of ip 0x0800
	ah->arp_hardwarelength = 6;        // �ϵ���������

	ah->arp_protocollength = 4;              // �������ݻ������
	ah->arp_opertaion = htons(0x0001);         // ���۷��̼��ڵ� req Ȥ�� resp   

	ah->src_mac[0] = mymac[0];		//my ���ּ�
	ah->src_mac[1] = mymac[1];
	ah->src_mac[2] = mymac[2];
	ah->src_mac[3] = mymac[3];
	ah->src_mac[4] = mymac[4];
	ah->src_mac[5] = mymac[5];

	ah->src_ip = myip;				//my ip

	ah->dest_mac[0] = 0x00;			//victim mac
	ah->dest_mac[1] = 0x00;
	ah->dest_mac[2] = 0x00;
	ah->dest_mac[3] = 0x00;
	ah->dest_mac[4] = 0x00;
	ah->dest_mac[5] = 0x00;

	ah->dest_ip = victimip;		//victim ip

	if (pcap_sendpacket(adhandle, (UCHAR*)packetdata, (sizeof(ethernet_HEADER) + sizeof(ARP_HEADER))) != 0) //pcap���� ����
	{
		printf("arp error\n");
	}
	else
	{
		int i;
		for (i = 0; i<(sizeof(ethernet_HEADER) + sizeof(ARP_HEADER)); i++)
			printf("0x%02x ", packetdata[i]);
		printf("\n arp send\n");
	}



};
