#include "winpcap.h"
#include <QMessageBox>
#include <QString>
#include <QDebug>
#include <QElapsedTimer>
#include <QTimer>

winpcap::winpcap(QWidget *parent)
	: QMainWindow(parent)
{
	qRegisterMetaType<m_StrDispalayinfo>("m_StrDispalayinfo");
	adjustwidget();

	// ������ȡ�߳�
	pcapthread_ = new PcapThread;
	timer_ = new QTimer(this);
	connect(timer_,SIGNAL(timeout()),pcapthread_,SLOT(timerUpDate()));
	//�������ݰ���Ϣ������
	connect(pcapthread_,SIGNAL(signalpcap(m_StrDispalayinfo)),this,SLOT(printTableInfo(m_StrDispalayinfo)));
	// ���ӿ�ʼ��ťΪ�߳���������
	connect(ui.runButton,SIGNAL(clicked()),this,SLOT(runclicked()));  
	// ������ѡ�У�����ʾ������ϸ��Ϣ
	connect(ui.listView,SIGNAL(clicked(QModelIndex)),this,
		SLOT(OnListItemClicked(QModelIndex)));
	//�����б� ����tableWidgetItem ����¼�
	connect(ui.tableWidget,SIGNAL(cellClicked(int,int)),this,
		SLOT(getTableItem(int,int)));
	//�򵥲�������
	connect(ui.filterComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(setFilterString(int)));

}


/* ��ʾץ����Ϣ */
void winpcap::printTableInfo(m_StrDispalayinfo StrDisInfo)
{
	// ���ù�����ʼ���ڵ׶�
	ui.tableWidget->scrollToBottom();
	// ����tableWidget���к�
	int nRow  = ui.tableWidget->rowCount();
	// ����row���˲���
	ui.tableWidget->insertRow(nRow);
	// �����б��е���Ŀ
	 if (nRow>=9999) //��Ȼ���������Խ��
	 {
		 nRow=0;
	 }
	QTableWidgetItem *item;
	// ���˽��źŴ���������д���Ӧ�������� 
	item = new QTableWidgetItem(StrDisInfo.msStrSurIpInfo); 
	ui.tableWidget->setItem(nRow, 1, item);
	item = new QTableWidgetItem(StrDisInfo.msStrSurMacInfo);
	ui.tableWidget->setItem(nRow, 2, item);
	item = new QTableWidgetItem(StrDisInfo.msStrDestIpInfo);
	ui.tableWidget->setItem(nRow, 3, item);
	item = new QTableWidgetItem(StrDisInfo.msStrDestMacInfo);
	ui.tableWidget->setItem(nRow, 4, item);
	item = new QTableWidgetItem(StrDisInfo.msStrProto);
	ui.tableWidget->setItem(nRow, 5, item);
	item = new QTableWidgetItem(StrDisInfo.msStrPackLen);
	ui.tableWidget->setItem(nRow, 6, item);
	item = new QTableWidgetItem(StrDisInfo.msStrsPort);
	ui.tableWidget->setItem(nRow, 7, item);
	item = new QTableWidgetItem(StrDisInfo.msStrdPort);
	ui.tableWidget->setItem(nRow, 8, item);
	 //�����������ݴ���������У������ʱ��ȡ
	g_nArraymap_.insert(nRow,StrDisInfo.g_pPktdata);
	// �洢�������ݱ�����
	g_nLenPktDataMap_.insert(nRow,StrDisInfo.msStrPackLen.toInt());
	int a=0;
}


void  winpcap::serchButton_Click()
{
	devcount_=0;		
	QMessageBox msg;
	unsigned int netmask;    //�������� 
	struct in_addr net_ip_address;
	u_int32_t net_ip;  
	char *net_ip_string;  
	struct in_addr net_mask_address;  
	u_int32_t net_mask;  
	char *net_mask_string;  
	// ������Ϣ�ݴ���errBuff,�豸
	char errBuf[PCAP_ERRBUF_SIZE],*pDevice;
	QString tempStr;
	if(pcap_findalldevs( &alldevs_, errbuf) == -1)  ////////ʹ��pcap_findalldevs��ʹ��pcap_findalldevs__ex�Ļ�����õ�����������Ͳ��ԣ���������
	{
		msg.setText(errbuf);
		msg.exec();
	}

	for(device_ = alldevs_; device_ != NULL;device_= device_->next)
	{
		devcount_++;
		tempStr=device_->name;
		listDevice_ += tempStr;
		model_->setStringList(listDevice_);
	}
	if(devcount_ == 0)
	{
		listDevice_ += "getDeviec error";
		model_->setStringList(listDevice_);
	}

	/* ɨ���б� */  
	for(device_=alldevs_;device_;device_=device_->next)  
	{  
	    qDebug("d->name:%s\n",device_->name);  
		qDebug("Description: %s\n",device_->description);  
		pcap_lookupnet(device_->name,&net_ip,&net_mask,errbuf);  
		net_ip_address.s_addr = net_ip;  
		net_ip_string = inet_ntoa(net_ip_address);//format  
		qDebug("net_ip_address: %s \n",net_ip_string);  
		net_mask_address.s_addr = net_mask;  
		net_mask_string = inet_ntoa(net_mask_address);//format  
		qDebug("net_mask_addres: %s \n",net_mask_string);  
		qDebug("\n");  
	} 
}


void  winpcap::OnListItemClicked(QModelIndex index)
{

	char errBuf[PCAP_ERRBUF_SIZE],*pDevice;
	bpf_u_int32 g_ipaddress,g_mipmask;
	char cherrbuf[1024];
	// ����ȡ����������ת����char��
	QByteArray ba = index.data().toString().toLatin1();
	// ����ȡ�������������߳�ʹ��
    //pcapthread_->g_pDevice = ba.data();
	pcapthread_->SetDevice(ba.data());
	ui.addrEdit->setText(QString("Surrcess getDevice: %1").arg(pcapthread_->GetDevice()));
	// �򿪻�ȡ������
	pcapthread_->SetHandle(pcap_open_live(pcapthread_->GetDevice(),65536,1 ,1000,errbuf));
	if(pcapthread_->GetDevice()== NULL)
	{
		// ��ʧ��
		perror(cherrbuf);
		exit(1);
	}
	if(pcap_lookupnet(pcapthread_->GetDevice(),&g_ipaddress,&g_mipmask,cherrbuf) ==- 1) ///
	{
		perror(cherrbuf);
		exit(1);
	}
	// ��ʾ������Ϣ
	else
	{
		char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];                    
		if(inet_ntop(AF_INET,&g_ipaddress,ip,sizeof(ip)) == NULL)
			perror("inet_ntop error");
		else if(inet_ntop(AF_INET,&g_mipmask,mask,sizeof(mask)) == NULL)
			perror("inet_ntop error");
		printf("IP address: %s, Network Mask: %s\n",ip,mask);
		//����ʾ�򿪵�������Ϣ
		QString sur_mac = QString("IP address: %1\nNetwork Mask: %2\n")
			.arg(ip).arg(mask);
		ui.addrEdit->append(sur_mac);
	}
}

/* �߳��������� */
void winpcap::runclicked()
{
	// �������
	ui.tableWidget->clearContents();
	if (ui.runButton->text()=="START")
	{
		ui.runButton->setText("STOP");
    	setDevsFilter("port 80"); //����˿�
		pcapthread_->start();
		timer_->start(200);///P;����ʶ���ˢ��Ƶ�ʴ����ÿ��30֡
	}
	else
	{
		ui.runButton->setText("START");
		pcapthread_->terminate();
		timer_->stop();
	}

}

/*  ��ӦtableWidget����Ŀ������¼� */
void winpcap::getTableItem(int row ,int)
{
	int i;
	char ch[10];
	ui.textEdit->clear();

	// ��ȡ������ĳ���
	QMap<int, int>::iterator g_nLen;
	g_nLen=g_nLenPktDataMap_.find(row);
	int nPackLen = g_nLen.value();
	QMap<int, const u_char*>::iterator mi;
	mi =g_nArraymap_.find(row);
	if (mi!=g_nArraymap_.end())
	{
		//  ��ʾ���������
		for(  i = 0; i < nPackLen; i++)
		{
			if(i%16 == 0)// ÿ����ʾ16������  i=0��16 ��32��n*16
			{
				sprintf(ch,"%04X  ",i);// ������   
				ui.textEdit->insertPlainText(QString("\n").append(ch));  /// ���� 0010
			}
			sprintf(ch,"%02X ",mi.value()[i]); 
			ui.textEdit->insertPlainText(ch);
		}
		ui.textEdit->insertPlainText("\n");

		// ��ӡ�ַ���Ϣ
		for(  i = 0; i < nPackLen; i++)
		{
			if(i%16 == 0)
			{
				ui.textEdit->insertPlainText(QString("\n     "));
			}
			if( (mi.value()[i] < 40 ) || (mi.value()[i] > 126 ))
			{
				ui.textEdit->insertPlainText(" .");
			}
			sprintf(ch," %c",mi.value()[i]);
		    ui.textEdit->insertPlainText(ch);
		}
	}
}


void winpcap::setFilterString(int index)
{
	switch (index)
	{
	case 0:
		filterString_ = "ip";
		break;
	case 1:
		filterString_ = "ip and tcp";
		break;
	case 2:
		filterString_ = "ip and udp";
		break;
	default:
		break;
	}
}


///////////////���ò���
bool winpcap::setDevsFilter(const char *szFilter)
{
	char cherrbuf[1024];
	// ���������·�㣬ֻ������̫��
	if ( pcap_datalink( pcapthread_->GetHandle()) != DLT_EN10MB ) {
		return false;
	}
	u_int netmask = 0xFFFFFF;
	if(pcap_lookupnet(alldevs_->name,&g_ipaddress_,&netmask,cherrbuf) ==- 1) ///
	{
		// ��ȡ������Ϣʧ��
		perror(cherrbuf);
		exit(1);
	}
	struct bpf_program fcode;
	// �������ʽת������������ʶ����ֽ���
	if (pcap_compile(pcapthread_->GetHandle(), &fcode, szFilter, 1, netmask) < 0) {
		pcap_freealldevs(alldevs_);
		return false;
	}
	if (pcap_setfilter(pcapthread_->GetHandle(), &fcode) < 0) {
		return false;
	}

	return true;
}


void winpcap:: adjustwidget() 
{

	//���
	ui.setupUi(this);
	// ���ñ��Ϊ��ֹ�༭
	ui.tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	// ���ñ��Ϊ���е�ѡ�з�ʽ
	ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
	// �����к��еĴ�СΪ������ƥ��
	// ui->tableWidget->resizeColumnsToContents();
	ui.tableWidget->resizeRowsToContents();
	// ���ò���ʾ������
	ui.tableWidget->setShowGrid(false);
	// ����ָ���еĿ��
	ui.tableWidget->setColumnWidth(0,50);
	ui.tableWidget->setColumnWidth(2,120);
	ui.tableWidget->setColumnWidth(4,120);
	ui.tableWidget->setColumnWidth(6,50);
	// ���ñ���
	setWindowTitle("winpcapTools");

	// �����б���ʾΪ�Զ�����
	model_ =  new QStringListModel;
	ui.listView->setModel(model_);
	ui.listView->setUpdatesEnabled(true);
}


winpcap::~winpcap()
{

}
