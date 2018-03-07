#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtGuiApplication2.h"
#include <QStandardItemModel>
#include <QStringListModel> 
#include <WinSock2.h>
#include <QTimer>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#define HAVE_REMOTE
#include <pcap.h>
#include <QVector>
#include <QDebug>
#include <QByteArray>
#include "Pthread.h"
#include "MutexQueue.h"
#include <QMutex>
class QtGuiApplication2 : public QMainWindow
{
	Q_OBJECT

public:
	QtGuiApplication2(QWidget *parent = Q_NULLPTR);
	~QtGuiApplication2();

private:
	Ui::QtGuiApplication2Class ui;
	PcapThread *pcapthread_;
private slots:
	void printTableInfo(m_StrDispalayinfo);  // 打印抓包信息
	void serchButton_Click();//搜索网卡列表
	void OnListItemClicked(QModelIndex index);// 打印网卡信息
	void runclicked();// 线程启动函数
	void stoprun();
	void getTableItem(int row, int);// 设置通过鼠标单击得到的单元格指针，进而获得其中文信息
	void setFilterString(int index); ///设置捕获函数字符
	void ApplyFilter();
	void OncurrentIndexChanged(int index);//动态修改网卡信息
	void OnTimeaddItem();
	void printprotocol(m_StrDispalayinfo);
protected:
	typedef struct _DEVInfo {
		QString name;
		QString description;
		QString familyName;
		QString address;
		QString netmask;
		QString loopback;
		QString Broadcast;
	}DEVInfo;
	void getAddr();
	char *QtGuiApplication2::iptos(u_long in);
	void QtGuiApplication2::ifprint(pcap_if_t *d);
	void ParserEthHeader(const u_char * p , QString & str);//解以太网首部
	void ParserIpHeader(const u_char * p , QString & str);///解IP数据包首部
	void ParserArpHeader(const u_char* p , QString& str);//ARP解析
	void ParserICMPHeader(const u_char* p, QString& str);//ICMP解析
	void ParserTCPHeader(const u_char* p, QString& str);//TCP协议解析
	void ParserUDPHeader(const u_char* p, QString& str);//UDO协议解析
private:
	pcap_if_t *alldevs_;
	pcap_if_t *device_;//设备网卡
	int devcount_; // 网卡数量
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 g_ipaddress_, g_ipmask_;
	QVector<DEVInfo> DEVList;
	QQueue<m_StrDispalayinfo> qpack;
	QQueue<m_StrDispalayinfo> qpackAfter;
	void comboBoxInit();
	bool ok;
private:
	//bool setDevsFilter(const char *szFilter);					// 对当前打开设备设置过滤器
	//void adjustwidget(); ///调整界面
public:
	QTimer *timer_;
	std::string filterString_;			// 过滤器设置字符串
	QMap<int, int> g_nLenPktDataMap_;
	QMap<int, const u_char*> g_nArraymap_;
	QMap<int, QString> g_info;
};
