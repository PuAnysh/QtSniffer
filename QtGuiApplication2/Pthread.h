
/***************************************************************/
//������Ҫ�Ƕ������ݰ��ĸ���ṹ���������̵߳����ݲ���
/***************************************************************/


#ifndef PCAPTHREAD_H
#define PCAPTHREAD_H

#include <QThread>
#include <winsock2.h>
#include <pcap.h>
#include <stdio.h>
#include <QMetaType>
#include "ui_winpcap.h"
#include <QQueue>

/* ��·�����ݰ���ʽ */
typedef struct
{
	u_char DestMac[6];
	u_char SrcMac[6];
	unsigned short Etype;  ////////////P:///////////��������������ݰ�������
}ETHHEADER;



/* ���ݰ�����*/ 
// IP���ݰ� ARP���ݰ�
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
#define ETHERTYPE_IP            0x0800          /* IP */                     
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */

// MAC Address Struct
struct MacAddr
{
	unsigned char a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	unsigned char f;
};

// IP Address Struct
struct IpAddr
{
	unsigned char a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
};


//    IP���ݰ�
typedef struct {
	unsigned char header_len:4; //// 4λ�ײ�����
	unsigned char version:4;    //4λ�汾
	unsigned char tos;         // ��������
	unsigned short total_len;  // �ܳ���
	unsigned short ident;       // ��ʶ
	unsigned short flags;     // �ֶ�ƫ��
	unsigned char ttl;          // ���ʱ��
	unsigned char proto;         	// Э��
	unsigned short checksum;     // �ײ�У���  
	u_char sourceIP[4];          // Դ��ַ
	u_char destIP[4];            // Ŀ�ĵ�ַ
}IPHEADER;


// ArpHeader Struct  ARP���ݰ�
struct ArpHeader
{
	unsigned short nHardType;		// Ӳ������
	unsigned short nProtoType;		// Э������
	unsigned char nMacLen;			// Ӳ����ַ����
	unsigned char nProtoLen;		// Э���ַ����
	unsigned short nOpCode;			// ��������
	MacAddr sSrcMac;				// ԴMAC��ַ
	IpAddr sSrcIp;					// ԴIP��ַ
	MacAddr sDstMac;				// Ŀ��MAC��ַ
	IpAddr sDstIp;					// Ŀ��IP��ַ
};


// ICMP Header Struct
struct IcmpHeader
{
	unsigned char nType;			// ��Ϣ����
	unsigned char nCode;			// ��Ϣ����
	unsigned short nCheckSum;		// У���
	// ...							// �򵥽�����ֻ����������ֶ�
};

// IGMP Header Struct
struct IgmpHeader
{
	unsigned char nType;			// ��Ϣ����
	unsigned char nCode;			// ��Ϣ����
	unsigned short nCheckSum;		// У���
	// ...							// �򵥽�����ֻ����������ֶ�
};


// TcpHeader Struct
struct TcpHeader
{
	unsigned short nSrcPort;		// ԭ�˿ں�
	unsigned short nDstPort;		// Ŀ�Ķ˿ں�
	unsigned long nSeqNum;			// ���к�
	unsigned long nAckNum;			// ȷ�����к�
	unsigned char rReserved1 : 4;	// ����
	unsigned char nHeaderLen : 4;	// ͷ������, ʵ����Ҫ����4
	unsigned char bFin : 1;			// FIN
	unsigned char bSyn : 1;			// SYN
	unsigned char bRst : 1;			// RST
	unsigned char bPsh : 1;			// PSH
	unsigned char bAck : 1;			// ACK
	unsigned char bUgr : 1;			// UGR
	unsigned char rReserved2 : 2;	// ����
	unsigned short nWinSize;		// ���ڴ�С
	unsigned short nCheckSum;		// У���
	unsigned short nUrgPtr;			// 16λ����ָ��
};

// UdpHeader Struct
struct UdpHeader
{
	unsigned short nSrcPort;		// ԭ�˿�
	unsigned short nDstPort;		// Ŀ�Ķ˿�
	unsigned short nLen;			// ���ݰ�����
	unsigned short nCrc;			// У���
};


///////////��������ʾ����Ϣ���ݣ����̷߳��͸����̵߳���Ϣ��
struct  m_StrDispalayinfo
{

	QString msStrSurIpInfo;
	QString msStrSurMacInfo;
	QString msStrDestIpInfo;
	QString msStrDestMacInfo;
	QString msStrProto;
	QString msStrPackLen;
	QString msStrsPort;
	QString msStrdPort;
	const u_char* g_pPktdata;
};

class winpcap;

/*��������QThread ������ PcapThread */
class PcapThread:public QThread
{
	Q_OBJECT

signals:
	// �̵߳��ź�
	void signalpcap( m_StrDispalayinfo);

public:
	PcapThread();
	void PcapThread::printTableInfo(m_StrDispalayinfo StrDisInfo,const u_char* pktData);

public:
	// �������ݰ�����
	void run();

private slots:
		void timerUpDate(); ///��ʱ�������� ˢ�������棬����ˢ��̫��������δ��Ӧ��

public:
	void ParserPaHeaderIfo();///���ͷ��Ϣ
	void ParserEthHeader(const u_char * p);//����̫���ײ�
	void ParserIpHeader(const u_char * p);///��IP���ݰ��ײ�
	void parserTcpHeader(const u_char * p);////��TCP�ײ�

private:
	QQueue<m_StrDispalayinfo> m_StrDisqueue_;///�������ݶ���

	/**��ͷ�õ��ı���*//////
	pcap_pkthdr* pHeader_;
	const u_char * pPktdata_; //���ݰ�
	int res;              
	struct tm *ltime_;
	time_t local_tv_sec_; //����ʱ��
	char timestr_[16];
	ETHHEADER *link_;  //��·��

	m_StrDispalayinfo msStrPlay;//����Ҫ��ʾ����Ϣ
	char *g_pDevice;
	pcap_t *g_phandle;
public:
	char *SetDevice(char *Device);
	char *GetDevice();
	pcap_t *SetHandle(pcap_t * handle);
	pcap_t *GetHandle();

public:
	void OnSetAdapter();//��ȡ�豸�ӿ�
};

#endif
