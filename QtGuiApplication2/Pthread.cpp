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

///* �������ݰ�����*/
void PcapThread::run()
{
	  struct bpf_program fcode;
	  char *pDevice;
	  // ��ȡ����ѡ��������豸
	  pDevice = g_pDevice;  
	  int datalink;

	 // ����ץ������Ϊ����ץ��
	 qDebug("---------------RUN-----------------\n");
	 IPHEADER *ip_header;
	 ArpHeader *ARPHeadr;
	 DWORD dwIpHdrLen;
	 TcpHeader *pTcpHdr;
	 UdpHeader *pUdpHdr;
	 int tempa;//��ʱ���Ա���
	 while( (res = pcap_next_ex(g_phandle,&pHeader_,&pPktdata_))>=0)
	 {
		  if(res==0)
		  {
			 /* ��ʱʱ�䵽 */
            continue;
		  }
		  /* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
        local_tv_sec_ = pHeader_->ts.tv_sec;
        ltime_=localtime(&local_tv_sec_);
        strftime( timestr_, sizeof timestr_, "%H:%M:%S", ltime_);
		static int tmpcountpacket = 1;		
		qDebug("**********************[%d]************************",tmpcountpacket++);
        qDebug("%s,%.6ld len:%d\n", timestr_, pHeader_->ts.tv_usec, pHeader_->len); //ʱ�䣬΢�����С  22:47:16,159922 len:60
		msStrPlay.msStrPackLen= QString::number(pHeader_->len);   ///����תstring   
		/////////////////�����ݰ�///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////��̫���ײ�
		ParserEthHeader(pPktdata_);
        //IPHEADER *ip_header;
		switch(ntohs(link_->Etype))
		{
			//////*** ����IP���ݰ�*****************************************************************************/////////////
			case ETHERTYPE_IP:
				 ParserIpHeader(pPktdata_);
						break;
		}
		msStrPlay.g_pPktdata=pPktdata_;
		m_StrDisqueue_.enqueue(msStrPlay);
	 }
}

void PcapThread::ParserEthHeader( const u_char * p)//����̫���ײ�
{
	char chSourMac[]="";
	char chDestMac[] = "";
	link_=(ETHHEADER*)p;
	//ԴMAC
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


void PcapThread:: ParserIpHeader(const u_char * p)///��IP���ݰ��ײ�
{
	IPHEADER *ip_header;
	ArpHeader *ARPHeadr;
	DWORD dwIpHdrLen;
	TcpHeader *pTcpHdr; ////TCP�ײ�
	UdpHeader *pUdpHdr;
	ip_header = (IPHEADER* )(p + sizeof(ETHHEADER));   
	dwIpHdrLen = ip_header->header_len*4;	// һ��Ҫ����4
	//ԴIP��ַ
	msStrPlay.msStrSurIpInfo = QString("%1.%2.%3.%4").arg(ip_header->sourceIP[0])
		.arg(ip_header->sourceIP[1]).arg(ip_header->sourceIP[2]).arg(ip_header->sourceIP[3]);
	//Ŀ��IP��ַ
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
					///////�ɽ����˿ں�	
					//pTcpHdr = (TcpHeader*)((BYTE*)ip_header +20 );  ///��ַƫ��20 ok
					pTcpHdr = (TcpHeader *)((BYTE*)ip_header + dwIpHdrLen);  ///ok
					msStrPlay.msStrsPort= QString::number(ntohs(pTcpHdr->nSrcPort));   ///����תstring   
					msStrPlay.msStrdPort=QString::number(ntohs(pTcpHdr->nDstPort));

					//////////////����httpЭ�飺***************************************//////////////////////////////
					int ip_len = ntohs(ip_header->total_len); /* get ip length, it contains header and body */   //��õĳ���ֵok ��wiresharkһ��
					int find_http = false;
					int FHTTP = false; //HTTP/1.1 200 OK
					int IsGet=false;
					int IsHttp=false;
					char* ip_pkt_data = (char*)ip_header;
					int n = 0;
					#define MAX_HTTP_BUFFER 99999
					char buffer[MAX_HTTP_BUFFER];  ///bufferԽ��
					char buffer_URL[100];
					int bufsize = 0; //http���ĳ�
					int urlbufsize = 0;
					for(; n<ip_len &&ip_len<MAX_HTTP_BUFFER; n++)
					{
						/* http get or post request */  //P:��Get��Post������������ Host
						if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
							|| (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
						{
							find_http = true;

						}
						//* http response */ //������Ӧ
						if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
						{
							find_http = true;
							FHTTP=true;
						}
						/* if http is found */
						if(find_http)
						{
							buffer[bufsize] = ip_pkt_data[n]; /* copy http data to buffer */
							bufsize ++;  /////////http���ĳ���
						}
					}
		
					/* print http content */
					if(find_http) {
						buffer[bufsize] = '\0';
						////���Խ���httpЭ�顢
						qDebug("***************************Startbuffer**********************************");
						qDebug("%s",buffer);
						qDebug("***************************Endbuffer**********************************");
						CHttpParser parser(buffer, bufsize);
						qDebug("hoststr:%s\n", (char*)parser.get_host().data());
						//URl:
						string Urlstr= parser.get_uri();
						char wholeurl[1024]= {'\0'};
						sprintf_s(wholeurl,"%s%s",(char*)parser.get_host().data(),(char *)Urlstr.data());
						qDebug("website is:%s",wholeurl); /////////���ʵ�ַ
					}

					break;
				}
			case 17:
				msStrPlay.msStrProto = QString("UDP");
				///////�ɽ����˿ں�
				pUdpHdr = (UdpHeader *)((BYTE*)ip_header + dwIpHdrLen);
				pUdpHdr = (UdpHeader *)(pPktdata_ +14+20 );
				qDebug("UDPSource port:%d",pUdpHdr->nSrcPort);
				qDebug("UDPDest port:%d",pUdpHdr->nDstPort);
				msStrPlay.msStrsPort= QString::number(pUdpHdr->nSrcPort);   ///����תstring   
				msStrPlay.msStrdPort=QString::number(pUdpHdr->nDstPort);
				break;
			default:
				msStrPlay.msStrProto = QString("UNKNOW");
				msStrPlay.msStrsPort = "";
				msStrPlay.msStrdPort = "";
				break;
	}

}


void PcapThread::timerUpDate()  //////�������淢����Ϣ
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