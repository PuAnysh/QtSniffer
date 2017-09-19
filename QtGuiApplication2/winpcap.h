#ifndef WINPCAP_H
#define WINPCAP_H

#include <QtWidgets/QMainWindow>
#include "ui_winpcap.h"
#include <QStandardItemModel>
#include <QStringListModel> 
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#define HAVE_REMOTE
#include <pcap.h>
#include <QVector>
#include "Pthread.h"
class winpcap : public QMainWindow
{
	Q_OBJECT

public:
	winpcap(QWidget *parent = 0);
	~winpcap();

private:
	Ui::winpcapClass ui;
	// 用于显示网卡列表
	QStringList listDevice_;
	QStringListModel *model_;
	PcapThread *pcapthread_;

private slots:
	void printTableInfo(m_StrDispalayinfo );  // 打印抓包信息
	void serchButton_Click();//搜索网卡列表
	void OnListItemClicked(QModelIndex index);// 打印网卡信息
	void runclicked();// 线程启动函数
	void getTableItem(int row ,int);// 设置通过鼠标单击得到的单元格指针，进而获得其中文信息
	void setFilterString(int index); ///设置捕获函数字符

private:
	pcap_if_t *alldevs_;
	pcap_if_t *device_;//设备网卡
	int devcount_  ; // 网卡数量
    char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 g_ipaddress_,g_ipmask_;


private:
	bool setDevsFilter(const char *szFilter);					// 对当前打开设备设置过滤器
	void adjustwidget() ; ///调整界面
public:
	QTimer *timer_;
	std::string filterString_;			// 过滤器设置字符串
	QMap<int,int> g_nLenPktDataMap_;
	QMap<int, const u_char*> g_nArraymap_;
};

#endif // WINPCAP_H
