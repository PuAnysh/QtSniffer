
/***************************************************************/
//该类主要是定义数据包的各层结构，还有子线程的数据捕获
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

/* 链路层数据包格式 */
typedef struct
{
	u_char DestMac[6];
	u_char SrcMac[6];
	unsigned short Etype;  ////////////P:///////////根据这个分析数据包的类型
}ETHHEADER;



/* 数据包类型*/ 
// IP数据包 ARP数据包
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


//    IP数据包
typedef struct {
	unsigned char header_len:4; //// 4位首部长度
	unsigned char version:4;    //4位版本
	unsigned char tos;         // 服务类型
	unsigned short total_len;  // 总长度
	unsigned short ident;       // 标识
	unsigned short flags;     // 分段偏移
	unsigned char ttl;          // 存活时间
	unsigned char proto;         	// 协议
	unsigned short checksum;     // 首部校验和  
	u_char sourceIP[4];          // 源地址
	u_char destIP[4];            // 目的地址
}IPHEADER;


// ArpHeader Struct  ARP数据包
struct ArpHeader
{
	unsigned short nHardType;		// 硬件类型
	unsigned short nProtoType;		// 协议类型
	unsigned char nMacLen;			// 硬件地址长度
	unsigned char nProtoLen;		// 协议地址长度
	unsigned short nOpCode;			// 操作类型
	MacAddr sSrcMac;				// 源MAC地址
	IpAddr sSrcIp;					// 源IP地址
	MacAddr sDstMac;				// 目标MAC地址
	IpAddr sDstIp;					// 目标IP地址
};


// ICMP Header Struct
struct IcmpHeader
{
	unsigned char nType;			// 消息类型
	unsigned char nCode;			// 消息代码
	unsigned short nCheckSum;		// 校验和
	// ...							// 简单解析，只定义上面的字段
};

// IGMP Header Struct
struct IgmpHeader
{
	unsigned char nType;			// 消息类型
	unsigned char nCode;			// 消息代码
	unsigned short nCheckSum;		// 校验和
	// ...							// 简单解析，只定义上面的字段
};


// TcpHeader Struct
struct TcpHeader
{
	unsigned short nSrcPort;		// 原端口号
	unsigned short nDstPort;		// 目的端口号
	unsigned long nSeqNum;			// 序列号
	unsigned long nAckNum;			// 确认序列号
	unsigned char rReserved1 : 4;	// 保留
	unsigned char nHeaderLen : 4;	// 头部长度, 实际需要乘以4
	unsigned char bFin : 1;			// FIN
	unsigned char bSyn : 1;			// SYN
	unsigned char bRst : 1;			// RST
	unsigned char bPsh : 1;			// PSH
	unsigned char bAck : 1;			// ACK
	unsigned char bUgr : 1;			// UGR
	unsigned char rReserved2 : 2;	// 保留
	unsigned short nWinSize;		// 窗口大小
	unsigned short nCheckSum;		// 校验和
	unsigned short nUrgPtr;			// 16位紧急指针
};

// UdpHeader Struct
struct UdpHeader
{
	unsigned short nSrcPort;		// 原端口
	unsigned short nDstPort;		// 目的端口
	unsigned short nLen;			// 数据包长度
	unsigned short nCrc;			// 校验和
};


///////////主界面显示的信息内容（子线程发送给主线程的消息）
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

/*　定义了QThread 的子类 PcapThread */
class PcapThread:public QThread
{
	Q_OBJECT

signals:
	// 线程的信号
	void signalpcap( m_StrDispalayinfo);

public:
	PcapThread();
	void PcapThread::printTableInfo(m_StrDispalayinfo StrDisInfo,const u_char* pktData);

public:
	// 捕获数据包函数
	void run();

private slots:
		void timerUpDate(); ///定时发送数据 刷新主界面，界面刷新太快会产生“未响应”

public:
	void ParserPaHeaderIfo();///解包头信息
	void ParserEthHeader(const u_char * p);//解以太网首部
	void ParserIpHeader(const u_char * p);///解IP数据包首部
	void parserTcpHeader(const u_char * p);////解TCP首部

private:
	QQueue<m_StrDispalayinfo> m_StrDisqueue_;///捕获数据队列

	/**包头用到的变量*//////
	pcap_pkthdr* pHeader_;
	const u_char * pPktdata_; //数据包
	int res;              
	struct tm *ltime_;
	time_t local_tv_sec_; //本机时间
	char timestr_[16];
	ETHHEADER *link_;  //链路层

	m_StrDispalayinfo msStrPlay;//界面要显示的信息
	char *g_pDevice;
	pcap_t *g_phandle;
public:
	char *SetDevice(char *Device);
	char *GetDevice();
	pcap_t *SetHandle(pcap_t * handle);
	pcap_t *GetHandle();

public:
	void OnSetAdapter();//获取设备接口
};

#endif
