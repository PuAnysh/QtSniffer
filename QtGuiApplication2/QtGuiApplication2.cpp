#include "QtGuiApplication2.h"

QtGuiApplication2::QtGuiApplication2(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	pcapthread_ = new PcapThread(&qpack);
	timer_ = new QTimer(this);
	ok = true;
	connect(ui.NetWorkcomboBox , SIGNAL(currentIndexChanged(int)) , this ,SLOT(OncurrentIndexChanged(int)));
	connect(timer_, SIGNAL(timeout()), this, SLOT(OnTimeaddItem()));
	connect(ui.BtnStart, SIGNAL(clicked()), this, SLOT(runclicked()));
	connect(ui.BtnStop, SIGNAL(clicked()), this, SLOT(stoprun()));
	connect(pcapthread_, SIGNAL(signalpcap(m_StrDispalayinfo)), this, SLOT(printTableInfo(m_StrDispalayinfo)));
	connect(ui.tableWidget, SIGNAL(cellClicked(int, int)), this,
		SLOT(getTableItem(int, int)));
	connect(ui.BtnApply ,SIGNAL(clicked()), this, SLOT(ApplyFilter()));
	getAddr();
	comboBoxInit();
}

QtGuiApplication2::~QtGuiApplication2() {

}

void QtGuiApplication2::printTableInfo(m_StrDispalayinfo StrDisInfo)
{
	// 设置滚动条始终在底端
	//ui.tableWidget->scrollToBottom();
	// 定义tableWidget中行号
	int nRow = ui.tableWidget->rowCount();
	// 根据row依此插入
	ui.tableWidget->insertRow(nRow);
	// 定义列表中的项目
	if (nRow >= 9999) //不然后面数组会越界
	{
		nRow = 0;
	}
	QTableWidgetItem *item;
	// 依此将信号传来的数据写如对应的行列中 
	item = new QTableWidgetItem(StrDisInfo.msStrSurIpInfo);
	ui.tableWidget->setItem(nRow, 0, item);
	item = new QTableWidgetItem(StrDisInfo.msStrSurMacInfo);
	ui.tableWidget->setItem(nRow, 1, item);
	item = new QTableWidgetItem(StrDisInfo.msStrDestIpInfo);
	ui.tableWidget->setItem(nRow, 2, item);
	item = new QTableWidgetItem(StrDisInfo.msStrDestMacInfo);
	ui.tableWidget->setItem(nRow, 3, item);
	item = new QTableWidgetItem(StrDisInfo.msStrProto);
	ui.tableWidget->setItem(nRow, 4, item);
	item = new QTableWidgetItem(StrDisInfo.msStrPackLen);
	ui.tableWidget->setItem(nRow, 5, item);
	item = new QTableWidgetItem(StrDisInfo.msStrsPort);
	ui.tableWidget->setItem(nRow, 6, item);
	item = new QTableWidgetItem(StrDisInfo.msStrdPort);
	ui.tableWidget->setItem(nRow, 7, item);
	//将产生的数据存放在数组中，备点击时读取
	g_nArraymap_.insert(nRow, StrDisInfo.g_pPktdata);
	//g_nArraymap_.append((char*)StrDisInfo.g_pPktdata);
	// 存储本次数据报长度
	g_nLenPktDataMap_.insert(nRow, StrDisInfo.msStrPackLen.toInt());
	g_info.insert(nRow, StrDisInfo.info);
	int a = 0;
}

void QtGuiApplication2::serchButton_Click()
{

}

void QtGuiApplication2::OnListItemClicked(QModelIndex index)
{
}

void QtGuiApplication2::runclicked()
{
//	allpack.clear();
	g_info.clear();
	qpackAfter.clear();
	g_nArraymap_.clear();
	g_nLenPktDataMap_.clear();
	ui.tableWidget->clearContents();
	ui.tableWidget->setRowCount(0);
	timer_->start(50);
	ok = false;
	pcapthread_->start();
}

void QtGuiApplication2::stoprun()
{
	//pcapthread_->terminate();
	pcapthread_->setFinshi();
	pcapthread_->quit();
	//timer_->stop();
	qDebug() << "Finishi";
	qDebug() << qpack.size();
	ok = true;
}

void QtGuiApplication2::getTableItem(int row, int)
{
	int i;
	char ch[10];
	ui.textEdit->clear();
	ui.textEditData->clear();
	// 获取捕获包的长度
	QMap<int, int>::iterator g_nLen;
	g_nLen = g_nLenPktDataMap_.find(row);
	int nPackLen = g_nLen.value();
	QMap<int, const u_char*>::iterator mi;
	mi = g_nArraymap_.find(row);
	if (mi != g_nArraymap_.end())
	{
		//  显示捕获的数据
		for (i = 0; i < nPackLen; i++)
		{
			if (i % 16 == 0)// 每行显示16个数据  i=0，16 ，32，n*16
			{
				sprintf(ch, "%04X  ", i);// 包计数   
				ui.textEditData->insertPlainText(QString("\n").append(ch));  /// 换行 0010
			}
			sprintf(ch, "%02X ", mi.value()[i]);
			ui.textEditData->insertPlainText(ch);
		}
		ui.textEditData->insertPlainText("\n");

		// 打印字符信息
		for (i = 0; i < nPackLen; i++)
		{
			if (i % 16 == 0)
			{
				ui.textEdit->insertPlainText(QString("\n"));
			}
			if ((mi.value()[i] < 40) || (mi.value()[i] > 126))
			{
				//ui.textEdit->insertPlainText(" .");
				sprintf(ch, " %c", '.');
			}
			else sprintf(ch, " %c", mi.value()[i]);
			ui.textEdit->insertPlainText(ch);
		}
	}
	ui.textEditProtocol->clear();
	//QString str;
	//ParserEthHeader(*mi, str);
	ui.textEditProtocol->insertPlainText(g_info[row]);
}

void QtGuiApplication2::setFilterString(int index)
{
}

void QtGuiApplication2::ApplyFilter()
{
	ui.tableWidget->clearContents();
	ui.tableWidget->setRowCount(0);
	QQueue<m_StrDispalayinfo>::iterator it;
	for (it = qpackAfter.begin(); it != qpackAfter.end(); it++) {
		if (ui.comboBoxprotocol->currentIndex() != 0) {
			if (it->msStrProto != ui.comboBoxprotocol->currentText())continue;
		}
		if (ui.lineEdit_SrcIP->text() != "") {
			if (it->msStrSurIpInfo != ui.lineEdit_SrcIP->text()) continue;
		}
		if (ui.lineEditDesIP->text() != "") {
			if (it->msStrDestIpInfo != ui.lineEditDesIP->text()) continue;
		}
		if (ui.lineEditSrcMAC->text() != "") {
			if (it->msStrSurMacInfo != ui.lineEditSrcMAC->text()) continue;
		}
		if (ui.lineEditDesMAC->text() != "") {
			if (it->msStrDestMacInfo != ui.lineEditDesMAC->text()) continue;
		}
		if (ui.lineEditSrcPort->text() != "") {
			if (it->msStrsPort != ui.lineEditSrcPort->text()) continue;
		}
		if (ui.lineEditDesPort->text() != "") {
			if (it->msStrdPort != ui.lineEditDesPort->text())continue;
		}
		printTableInfo(*it);
	}
}

void QtGuiApplication2::OncurrentIndexChanged(int index)
{
	char errBuf[PCAP_ERRBUF_SIZE], *pDevice;
	bpf_u_int32 g_ipaddress, g_mipmask;
	char cherrbuf[1024];
	DEVInfo dev = DEVList[index];
	QByteArray ba = dev.name.toLatin1();
	qDebug() << index;
	// 将获取到的网卡传回线程使用
	//pcapthread_->g_pDevice = ba.data();
	pcapthread_->SetDevice(ba.data());
	pcapthread_->SetHandle(pcap_open_live(pcapthread_->GetDevice(), 65536, 1, 1000, errbuf));
	// 打开获取的网卡
	pcapthread_->SetHandle(pcap_open_live(pcapthread_->GetDevice(), 65536, 1, 1000, errbuf));
	if (pcapthread_->GetDevice() == NULL)
	{
		// 打开失败
		perror(cherrbuf);
		exit(1);
	}
	if (pcap_lookupnet(pcapthread_->GetDevice(), &g_ipaddress, &g_mipmask, cherrbuf) == -1) ///
	{
		perror(cherrbuf);
		exit(1);
	}
	else {
		//打印信息到界面上
		ui.LineEditNetworkName->setText(dev.name);
		ui.LineEditDecription->setText(dev.description);
		ui.LineEditIPAddtress->setText(dev.address);
		ui.LineEditNetworkMask->setText(dev.netmask);
	}
}

void QtGuiApplication2::OnTimeaddItem()
{
	//qDebug() << "OnTimeaddItem";
	for (int i = 0; i < 100 && !qpack.empty(); i++){
		mutex.lock();
		printTableInfo(qpack.front());
		qpackAfter.push_back(qpack.front());
		qpack.pop_front();
		mutex.unlock();
	}
	if (ok && qpack.size() == 0) {
		timer_->stop();
		qDebug() << "OK ADDing";
	}
}

void QtGuiApplication2::printprotocol(m_StrDispalayinfo info)
{
	QString str;
	if (info.msStrProto == "TCP") {

	}
	else if (info.msStrProto == "UDP") {

	}
	else if (info.msStrProto == "ARP") {

	}
	else if (info.msStrProto == "ICMP") {

	}
}


void QtGuiApplication2::getAddr()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	struct in_addr net_ip_address;//网卡IP信息,在pcap.h里面有定义  
	u_int32_t net_ip;
	char *net_ip_string;

	struct in_addr net_mask_address;
	u_int32_t net_mask;
	char *net_mask_string;

	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)//无法找到网卡列表  
	{
		fprintf(stderr, "error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* 扫描列表 */
	
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d);
	}

	/* 释放链表 */
	pcap_freealldevs(alldevs);
	printf("\n");
}

/* 来自 tcptracert, 把数字IP地址转换为点格式 */
#define IPTOSBUFFERS 12
char *QtGuiApplication2::iptos(u_long in) {
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

void QtGuiApplication2::ifprint(pcap_if_t *d) {
	pcap_addr_t *a;
	DEVInfo dev;
	/* 名称 */
	printf("%s\n", d->name);
	dev.name = d->name;
	/* 描述 */
	if (d->description) {
		printf("\tDescription: %s\n", d->description);
		dev.description =  d->description;
	}

	/* 回环地址 */
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	dev.loopback = (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no";
	/* IP 地址 */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family) {
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr) {
				/* Y- IP 地址 */
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				dev.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
			}
			if (a->netmask) {
				/* Y- 掩码 */
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
				dev.netmask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
			}
			if (a->broadaddr) {
				/* Y- 广播地址 */
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
				dev.Broadcast = iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
			}
			if (a->dstaddr) {
				/* Y - 目标地址 */
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			}
			break;
		default:
			/* 未知 */
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	DEVList.append(dev);
	printf("\n");
}

void QtGuiApplication2::ParserEthHeader(const u_char * p, QString & str)
{
	QString tmp = "============ETHHEADER=============\n";
	str.append(tmp);
	char chSourMac[100] = "";
	char chDestMac[100] = "";
	ETHHEADER* link_;
	link_ = (ETHHEADER*)p;
	//源MAC

	sprintf(chSourMac, "%02X-%02X-%02X-%02X-%02X-%02X\n", link_->SrcMac[0],
		link_->SrcMac[1], link_->SrcMac[2],
		link_->SrcMac[3], link_->SrcMac[4],
		link_->SrcMac[5]);
	str.append(QString("Source MAC: ") + QString(chSourMac)+"\n");
	
	sprintf(chDestMac, "%02X-%02X-%02X-%02X-%02X-%02X\n", link_->DestMac[0],
		link_->DestMac[1], link_->DestMac[2],
		link_->DestMac[3], link_->DestMac[4],
		link_->DestMac[5]);
	str.append(QString("Destination MAC: ") + QString(chDestMac)+ "\n");
	str.append(QString("TYPE: ") + QString::number(ntohs(link_->Etype)) + "\n");
	switch (ntohs(link_->Etype))
	{
	case ETHERTYPE_IP:
		ParserIpHeader(p , str);
		break;
	case  ETHERTYPE_ARP:
		ParserArpHeader(p, str);
		break;
	default:
		qDebug() << "UKNOW";
		break;
	}
}
/*
//    IP数据包
typedef struct {
unsigned char header_len:4; //// 4位首部长度
unsigned char version:4;    //4位版本
unsigned char tos;         // 服务类型
unsigned short total_len;  // 总长度
unsigned short ident;       // 标识
unsigned short flags;     // 分段偏移
unsigned char ttl;          // 存活时间
unsigned char proto;         // 协议
unsigned short checksum;     // 首部校验和
u_char sourceIP[4];          // 源地址
u_char destIP[4];            // 目的地址
}IPHEADER;
*/
void QtGuiApplication2::ParserIpHeader(const u_char * p, QString & str)
{
	QString tmp = "=============IPHEADER==============\n";
	str.append(tmp);
	IPHEADER *ip_header;
	ArpHeader *ARPHeadr;
	DWORD dwIpHdrLen;
	ip_header = (IPHEADER*)(p + sizeof(ETHHEADER));
	dwIpHdrLen = ip_header->header_len * 4;	// 一定要乘以4
											//源IP地址
	str.append(QString("header_len:") + QString::number(ntohs(ip_header->header_len))+QString("\n"));
	str.append(QString("version:") + QString::number(ntohs(ip_header->version)) + QString("\n"));
	str.append(QString("tos:") + QString::number(ntohs(ip_header->tos)) + QString("\n"));
	str.append(QString("total_len:") + QString::number(ntohs(ip_header->total_len)) + QString("\n"));
	str.append(QString("ident:") + QString::number(ntohs(ip_header->ident)) + QString("\n"));
	str.append(QString("flags:") + QString::number(ntohs(ip_header->flags)) + QString("\n"));
	str.append(QString("ttl:") + QString::number(ntohs(ip_header->ttl)) + QString("\n"));
	str.append(QString("proto:") + QString::number(ntohs(ip_header->proto)) + QString("\n"));
	str.append(QString("checksum:") + QString::number(ntohs(ip_header->checksum)) + QString("\n"));

	QString tmp1 = QString("%1.%2.%3.%4").arg(ip_header->sourceIP[0])
		.arg(ip_header->sourceIP[1]).arg(ip_header->sourceIP[2]).arg(ip_header->sourceIP[3]);
	//目的IP地址
	str.append(QString("sourceIP:") + tmp1 + QString("\n"));
	QString tmp2 = QString("%1.%2.%3.%4").arg(ip_header->destIP[0])
		.arg(ip_header->destIP[1]).arg(ip_header->destIP[2]).arg(ip_header->destIP[3]);
	str.append(QString("destIP:") + tmp2 + QString("\n"));
	switch (ntohs(ip_header->proto))
	{
	case 1:
		ParserICMPHeader(p+ dwIpHdrLen,str);//ICMP解析
		break;
	case 6:
	{
		ParserTCPHeader(p + dwIpHdrLen, str);
		break;
	}
	case 17:
		ParserUDPHeader(p + dwIpHdrLen, str);
		break;
	default:
		
		break;
	}

}
/*
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
*/
void QtGuiApplication2::ParserArpHeader(const u_char * p, QString & str)
{
	ArpHeader *pArpHdr; ////ARP首部
	pArpHdr = (ArpHeader*)((BYTE*)p + sizeof(ETHHEADER));
	QString tmp = "=============ArpHeader=============\n";
	str.append(tmp);
	str.append(QString("HardType:" + QString::number(pArpHdr->nHardType) + QString("\n")));
	str.append(QString("ProtoType:" + QString::number(pArpHdr->nHardType) + QString("\n")));
	str.append(QString("MacLen:" + QString::number(pArpHdr->nMacLen) + QString("\n")));
	str.append(QString("ProtoLen:" + QString::number(pArpHdr->nProtoLen) + QString("\n")));
	str.append(QString("OpCode:" + QString::number(pArpHdr->nOpCode) + QString("\n")));
	QString tmp1 = QString("%1.%2.%3.%4").arg(pArpHdr->sSrcIp.a)
		.arg(pArpHdr->sSrcIp.b).arg(pArpHdr->sSrcIp.c).arg(pArpHdr->sSrcIp.d);

	QString tmp2 = QString("%1.%2.%3.%4").arg(pArpHdr->sDstIp.a)
		.arg(pArpHdr->sDstIp.b).arg(pArpHdr->sDstIp.c).arg(pArpHdr->sDstIp.d);
	char chSourMac[100] = "";
	char chDestMac[100] = "";
	//源MAC
	sprintf(chSourMac, "%02X-%02X-%02X-%02X-%02X-%02X", pArpHdr->sSrcMac.a,
		pArpHdr->sSrcMac.b, pArpHdr->sSrcMac.c,
		pArpHdr->sSrcMac.d, pArpHdr->sSrcMac.e,
		pArpHdr->sSrcMac.f);
	sprintf(chDestMac, "%02X-%02X-%02X-%02X-%02X-%02X", pArpHdr->sDstMac.a,
		pArpHdr->sDstMac.b, pArpHdr->sDstMac.c,
		pArpHdr->sDstMac.d, pArpHdr->sDstMac.e,
		pArpHdr->sDstMac.f);
	QString tmp3 = QString(chSourMac);
	QString tmp4 = QString(chDestMac);
	str.append(QString("SrcMAC:" + tmp2 + QString("\n")));
	str.append(QString("SrcIP:" + tmp1 + QString("\n")));
	str.append(QString("DestMAC:" + tmp4 + QString("\n")));
	str.append(QString("DestIP:" + tmp3 + QString("\n")));
}

/*
// ICMP Header Struct
struct IcmpHeader
{
unsigned char nType;			// 消息类型
unsigned char nCode;			// 消息代码
unsigned short nCheckSum;		// 校验和
// ...							// 简单解析，只定义上面的字段
};
*/

void QtGuiApplication2::ParserICMPHeader(const u_char * p, QString & str)
{
	IcmpHeader* icmphead = (IcmpHeader*)(p);
	QString tmp = "============ICMPHeader============\n";
	str.append(tmp);
	str.append(QString("Type:" + icmphead->nType + QString("\n")));
	str.append(QString("Code:" + icmphead->nType + QString("\n")));
	str.append(QString("CheckSum:" + icmphead->nType + QString("\n")));
}
/*
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
*/
void QtGuiApplication2::ParserTCPHeader(const u_char * p, QString & str)
{
	TcpHeader* tcphead = (TcpHeader*)((BYTE*)p);
	QString tmp = QString("==============TCPHeader===========\n");
	str.append(tmp);
	str.append(QString("SrcPort:" + QString::number(tcphead->nSrcPort) + "\n"));
	str.append(QString("DstPort:" + QString::number(tcphead->nDstPort) + "\n"));
	str.append(QString("SeqNum:" + QString::number(tcphead->nSeqNum) + "\n"));
	str.append(QString("AckNum:" + QString::number(tcphead->nAckNum) + "\n"));
	str.append(QString("HeaderLen:" + QString::number(tcphead->nHeaderLen) + "\n"));
	str.append(QString("Fin:" + QString::number(tcphead->bFin) + "\n"));
	str.append(QString("Syn:" + QString::number(tcphead->bSyn) + "\n"));
	str.append(QString("Rst:" + QString::number(tcphead->bRst) + "\n"));
	str.append(QString("Psh:" + QString::number(tcphead->bPsh) + "\n"));
	str.append(QString("Ack:" + QString::number(tcphead->bAck) + "\n"));
	str.append(QString("Ugr:" + QString::number(tcphead->bUgr) + "\n"));
	str.append(QString("WinSize:" + QString::number(tcphead->nWinSize) + "\n"));
	str.append(QString("CheckSum:" + QString::number(tcphead->nCheckSum) + "\n"));
	str.append(QString("UrgPtr:" + QString::number(tcphead->nUrgPtr) + "\n"));
}

void QtGuiApplication2::ParserUDPHeader(const u_char * p, QString & str)
{
}

void QtGuiApplication2::comboBoxInit()
{
	for (int i = 0; i < DEVList.size(); i++) {
		ui.NetWorkcomboBox->addItem(DEVList[i].name);
	}
}
