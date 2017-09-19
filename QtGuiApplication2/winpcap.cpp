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

	// 创建获取线程
	pcapthread_ = new PcapThread;
	timer_ = new QTimer(this);
	connect(timer_,SIGNAL(timeout()),pcapthread_,SLOT(timerUpDate()));
	//线束数据包信息到界面
	connect(pcapthread_,SIGNAL(signalpcap(m_StrDispalayinfo)),this,SLOT(printTableInfo(m_StrDispalayinfo)));
	// 连接开始按钮为线程启动功能
	connect(ui.runButton,SIGNAL(clicked()),this,SLOT(runclicked()));  
	// 网卡被选中，并显示网卡详细信息
	connect(ui.listView,SIGNAL(clicked(QModelIndex)),this,
		SLOT(OnListItemClicked(QModelIndex)));
	//单击列表 设置tableWidgetItem 点击事件
	connect(ui.tableWidget,SIGNAL(cellClicked(int,int)),this,
		SLOT(getTableItem(int,int)));
	//简单捕获设置
	connect(ui.filterComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(setFilterString(int)));

}


/* 显示抓包信息 */
void winpcap::printTableInfo(m_StrDispalayinfo StrDisInfo)
{
	// 设置滚动条始终在底端
	ui.tableWidget->scrollToBottom();
	// 定义tableWidget中行号
	int nRow  = ui.tableWidget->rowCount();
	// 根据row依此插入
	ui.tableWidget->insertRow(nRow);
	// 定义列表中的项目
	 if (nRow>=9999) //不然后面数组会越界
	 {
		 nRow=0;
	 }
	QTableWidgetItem *item;
	// 依此将信号传来的数据写如对应的行列中 
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
	 //将产生的数据存放在数组中，备点击时读取
	g_nArraymap_.insert(nRow,StrDisInfo.g_pPktdata);
	// 存储本次数据报长度
	g_nLenPktDataMap_.insert(nRow,StrDisInfo.msStrPackLen.toInt());
	int a=0;
}


void  winpcap::serchButton_Click()
{
	devcount_=0;		
	QMessageBox msg;
	unsigned int netmask;    //子网掩码 
	struct in_addr net_ip_address;
	u_int32_t net_ip;  
	char *net_ip_string;  
	struct in_addr net_mask_address;  
	u_int32_t net_mask;  
	char *net_mask_string;  
	// 定义信息容错处理errBuff,设备
	char errBuf[PCAP_ERRBUF_SIZE],*pDevice;
	QString tempStr;
	if(pcap_findalldevs( &alldevs_, errbuf) == -1)  ////////使用pcap_findalldevs，使用pcap_findalldevs__ex的话后面得到的子网掩码就不对，。。。。
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

	/* 扫描列表 */  
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
	// 将获取到的网卡名转换成char型
	QByteArray ba = index.data().toString().toLatin1();
	// 将获取到的网卡传回线程使用
    //pcapthread_->g_pDevice = ba.data();
	pcapthread_->SetDevice(ba.data());
	ui.addrEdit->setText(QString("Surrcess getDevice: %1").arg(pcapthread_->GetDevice()));
	// 打开获取的网卡
	pcapthread_->SetHandle(pcap_open_live(pcapthread_->GetDevice(),65536,1 ,1000,errbuf));
	if(pcapthread_->GetDevice()== NULL)
	{
		// 打开失败
		perror(cherrbuf);
		exit(1);
	}
	if(pcap_lookupnet(pcapthread_->GetDevice(),&g_ipaddress,&g_mipmask,cherrbuf) ==- 1) ///
	{
		perror(cherrbuf);
		exit(1);
	}
	// 显示网卡信息
	else
	{
		char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];                    
		if(inet_ntop(AF_INET,&g_ipaddress,ip,sizeof(ip)) == NULL)
			perror("inet_ntop error");
		else if(inet_ntop(AF_INET,&g_mipmask,mask,sizeof(mask)) == NULL)
			perror("inet_ntop error");
		printf("IP address: %s, Network Mask: %s\n",ip,mask);
		//　显示打开的网卡信息
		QString sur_mac = QString("IP address: %1\nNetwork Mask: %2\n")
			.arg(ip).arg(mask);
		ui.addrEdit->append(sur_mac);
	}
}

/* 线程启动函数 */
void winpcap::runclicked()
{
	// 清除内容
	ui.tableWidget->clearContents();
	if (ui.runButton->text()=="START")
	{
		ui.runButton->setText("STOP");
    	setDevsFilter("port 80"); //捕获端口
		pcapthread_->start();
		timer_->start(200);///P;人眼识别的刷新频率大概在每秒30帧
	}
	else
	{
		ui.runButton->setText("START");
		pcapthread_->terminate();
		timer_->stop();
	}

}

/*  响应tableWidget中项目被点击事件 */
void winpcap::getTableItem(int row ,int)
{
	int i;
	char ch[10];
	ui.textEdit->clear();

	// 获取捕获包的长度
	QMap<int, int>::iterator g_nLen;
	g_nLen=g_nLenPktDataMap_.find(row);
	int nPackLen = g_nLen.value();
	QMap<int, const u_char*>::iterator mi;
	mi =g_nArraymap_.find(row);
	if (mi!=g_nArraymap_.end())
	{
		//  显示捕获的数据
		for(  i = 0; i < nPackLen; i++)
		{
			if(i%16 == 0)// 每行显示16个数据  i=0，16 ，32，n*16
			{
				sprintf(ch,"%04X  ",i);// 包计数   
				ui.textEdit->insertPlainText(QString("\n").append(ch));  /// 换行 0010
			}
			sprintf(ch,"%02X ",mi.value()[i]); 
			ui.textEdit->insertPlainText(ch);
		}
		ui.textEdit->insertPlainText("\n");

		// 打印字符信息
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


///////////////设置捕获
bool winpcap::setDevsFilter(const char *szFilter)
{
	char cherrbuf[1024];
	// 检查数据链路层，只考虑以太网
	if ( pcap_datalink( pcapthread_->GetHandle()) != DLT_EN10MB ) {
		return false;
	}
	u_int netmask = 0xFFFFFF;
	if(pcap_lookupnet(alldevs_->name,&g_ipaddress_,&netmask,cherrbuf) ==- 1) ///
	{
		// 获取网卡信息失败
		perror(cherrbuf);
		exit(1);
	}
	struct bpf_program fcode;
	// 布尔表达式转换过滤引擎能识别的字节码
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

	//表格：
	ui.setupUi(this);
	// 设置表格为禁止编辑
	ui.tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	// 设置表格为整行的选中方式
	ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
	// 设置行和列的大小为与内容匹配
	// ui->tableWidget->resizeColumnsToContents();
	ui.tableWidget->resizeRowsToContents();
	// 设置不显示格子线
	ui.tableWidget->setShowGrid(false);
	// 设置指定列的宽度
	ui.tableWidget->setColumnWidth(0,50);
	ui.tableWidget->setColumnWidth(2,120);
	ui.tableWidget->setColumnWidth(4,120);
	ui.tableWidget->setColumnWidth(6,50);
	// 设置标题
	setWindowTitle("winpcapTools");

	// 网卡列表显示为自动更新
	model_ =  new QStringListModel;
	ui.listView->setModel(model_);
	ui.listView->setUpdatesEnabled(true);
}


winpcap::~winpcap()
{

}
