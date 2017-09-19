#include "Pthread.h"
#include <QDebug>
#include "http_util.h"
#include <QTimer>

 PcapThread::PcapThread()
 {

 }

 char *PcapThread::SetDevice(char *Device)
 {
	g_pDevice=Device;
    return g_pDevice;   
 }
 char *PcapThread::GetDevice()
 {
    return g_pDevice;
 }

 pcap_t *  PcapThread::SetHandle( pcap_t * handle)
 {
	g_phandle=handle;
	return g_phandle;
 }

 pcap_t * PcapThread::GetHandle()
 {
	 return g_phandle;
 }

///* 捕获数据包函数*/
void PcapThread::run()
{
	  struct bpf_program fcode;
	  char *pDevice;
	  // 获取界面选择的网卡设备
	  pDevice = g_pDevice;  
	  int datalink;

	 // 设置抓包规则为无限抓包
	 qDebug("---------------RUN-----------------\n");
	 IPHEADER *ip_header;
	 ArpHeader *ARPHeadr;
	 DWORD dwIpHdrLen;
	 TcpHeader *pTcpHdr;
	 UdpHeader *pUdpHdr;
	 int tempa;//临时调试变量
	 while( (res = pcap_next_ex(g_phandle,&pHeader_,&pPktdata_))>=0)
	 {
		  if(res==0)
		  {
			 /* 超时时间到 */
            continue;
		  }
		  /* 将时间戳转换成可识别的格式 */
        local_tv_sec_ = pHeader_->ts.tv_sec;
        ltime_=localtime(&local_tv_sec_);
        strftime( timestr_, sizeof timestr_, "%H:%M:%S", ltime_);
		static int tmpcountpacket = 1;		
		qDebug("**********************[%d]************************",tmpcountpacket++);
        qDebug("%s,%.6ld len:%d\n", timestr_, pHeader_->ts.tv_usec, pHeader_->len); //时间，微妙，包大小  22:47:16,159922 len:60
		msStrPlay.msStrPackLen= QString::number(pHeader_->len);   ///数字转string   
		/////////////////解数据包///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////以太网首部
		ParserEthHeader(pPktdata_);
        //IPHEADER *ip_header;
		switch(ntohs(link_->Etype))
		{
			//////*** 解析IP数据包*****************************************************************************/////////////
			case ETHERTYPE_IP:
				 ParserIpHeader(pPktdata_);
						break;
		}
		msStrPlay.g_pPktdata=pPktdata_;
		m_StrDisqueue_.enqueue(msStrPlay);
	 }
}

void PcapThread::ParserEthHeader( const u_char * p)//解以太网首部
{
	char chSourMac[]="";
	char chDestMac[] = "";
	link_=(ETHHEADER*)p;
	//源MAC
	sprintf(chSourMac,"%02X-%02X-%02X-%02X-%02X-%02X",link_->SrcMac[0],
		link_->SrcMac[1],link_->SrcMac[2],
		link_->SrcMac[3],link_->SrcMac[4],
		link_->SrcMac[5]);
	msStrPlay.msStrSurMacInfo = QString(chSourMac);
	qDebug("SrcMAC=%s",msStrPlay.msStrSurMacInfo.toStdString().c_str());
	sprintf(chDestMac,"%02X-%02X-%02X-%02X-%02X-%02X",link_->DestMac[0],
		link_->DestMac[1],link_->DestMac[2],
		link_->DestMac[3],link_->DestMac[4],
		link_->DestMac[5]);
	msStrPlay.msStrDestMacInfo = QString(chDestMac);
	qDebug("DestMAC= %s \n",msStrPlay.msStrDestMacInfo.toStdString().c_str());

}


void PcapThread:: ParserIpHeader(const u_char * p)///解IP数据包首部
{
	IPHEADER *ip_header;
	ArpHeader *ARPHeadr;
	DWORD dwIpHdrLen;
	TcpHeader *pTcpHdr; ////TCP首部
	UdpHeader *pUdpHdr;
	ip_header = (IPHEADER* )(p + sizeof(ETHHEADER));   
	dwIpHdrLen = ip_header->header_len*4;	// 一定要乘以4
	//源IP地址
	msStrPlay.msStrSurIpInfo = QString("%1.%2.%3.%4").arg(ip_header->sourceIP[0])
		.arg(ip_header->sourceIP[1]).arg(ip_header->sourceIP[2]).arg(ip_header->sourceIP[3]);
	//目的IP地址
	msStrPlay.msStrDestIpInfo = QString("%1.%2.%3.%4").arg(ip_header->destIP[0])
		.arg(ip_header->destIP[1]).arg(ip_header->destIP[2]).arg(ip_header->destIP[3]);

	switch (ip_header->proto)
	{
			case 1:
				msStrPlay.msStrProto = QString("ICMP");
				msStrPlay.msStrsPort = "";
				msStrPlay.msStrdPort = "";
				break;
			case 6:
				{	
					msStrPlay.msStrProto = QString("TCP");
					///////可解析端口号	
					//pTcpHdr = (TcpHeader*)((BYTE*)ip_header +20 );  ///地址偏移20 ok
					pTcpHdr = (TcpHeader *)((BYTE*)ip_header + dwIpHdrLen);  ///ok
					msStrPlay.msStrsPort= QString::number(ntohs(pTcpHdr->nSrcPort));   ///数字转string   
					msStrPlay.msStrdPort=QString::number(ntohs(pTcpHdr->nDstPort));

					//////////////解析http协议：***************************************//////////////////////////////
					int ip_len = ntohs(ip_header->total_len); /* get ip length, it contains header and body */   //获得的长度值ok 和wireshark一样
					int find_http = false;
					int FHTTP = false; //HTTP/1.1 200 OK
					int IsGet=false;
					int IsHttp=false;
					char* ip_pkt_data = (char*)ip_header;
					int n = 0;
					#define MAX_HTTP_BUFFER 99999
					char buffer[MAX_HTTP_BUFFER];  ///buffer越界
					char buffer_URL[100];
					int bufsize = 0; //http报文长
					int urlbufsize = 0;
					for(; n<ip_len &&ip_len<MAX_HTTP_BUFFER; n++)
					{
						/* http get or post request */  //P:在Get和Post的请求包里才有 Host
						if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
							|| (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
						{
							find_http = true;

						}
						//* http response */ //请求响应
						if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
						{
							find_http = true;
							FHTTP=true;
						}
						/* if http is found */
						if(find_http)
						{
							buffer[bufsize] = ip_pkt_data[n]; /* copy http data to buffer */
							bufsize ++;  /////////http报文长度
						}
					}
		
					/* print http content */
					if(find_http) {
						buffer[bufsize] = '\0';
						////测试解析http协议、
						qDebug("***************************Startbuffer**********************************");
						qDebug("%s",buffer);
						qDebug("***************************Endbuffer**********************************");
						CHttpParser parser(buffer, bufsize);
						qDebug("hoststr:%s\n", (char*)parser.get_host().data());
						//URl:
						string Urlstr= parser.get_uri();
						char wholeurl[1024]= {'\0'};
						sprintf_s(wholeurl,"%s%s",(char*)parser.get_host().data(),(char *)Urlstr.data());
						qDebug("website is:%s",wholeurl); /////////访问地址
					}

					break;
				}
			case 17:
				msStrPlay.msStrProto = QString("UDP");
				///////可解析端口号
				pUdpHdr = (UdpHeader *)((BYTE*)ip_header + dwIpHdrLen);
				pUdpHdr = (UdpHeader *)(pPktdata_ +14+20 );
				qDebug("UDPSource port:%d",pUdpHdr->nSrcPort);
				qDebug("UDPDest port:%d",pUdpHdr->nDstPort);
				msStrPlay.msStrsPort= QString::number(pUdpHdr->nSrcPort);   ///数字转string   
				msStrPlay.msStrdPort=QString::number(pUdpHdr->nDstPort);
				break;
			default:
				msStrPlay.msStrProto = QString("UNKNOW");
				msStrPlay.msStrsPort = "";
				msStrPlay.msStrdPort = "";
				break;
	}

}


void PcapThread::timerUpDate()  //////向主界面发送消息
{
	m_StrDispalayinfo teminfo;
	if(!m_StrDisqueue_.isEmpty())
	{
	   teminfo=m_StrDisqueue_.dequeue();
	   emit signalpcap(teminfo);
	}
}

void PcapThread:: OnSetAdapter()
{

}