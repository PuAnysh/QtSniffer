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
	void printTableInfo(m_StrDispalayinfo);  // ��ӡץ����Ϣ
	void serchButton_Click();//���������б�
	void OnListItemClicked(QModelIndex index);// ��ӡ������Ϣ
	void runclicked();// �߳���������
	void stoprun();
	void getTableItem(int row, int);// ����ͨ����굥���õ��ĵ�Ԫ��ָ�룬���������������Ϣ
	void setFilterString(int index); ///���ò������ַ�
	void ApplyFilter();
	void OncurrentIndexChanged(int index);//��̬�޸�������Ϣ
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
	void ParserEthHeader(const u_char * p , QString & str);//����̫���ײ�
	void ParserIpHeader(const u_char * p , QString & str);///��IP���ݰ��ײ�
	void ParserArpHeader(const u_char* p , QString& str);//ARP����
	void ParserICMPHeader(const u_char* p, QString& str);//ICMP����
	void ParserTCPHeader(const u_char* p, QString& str);//TCPЭ�����
	void ParserUDPHeader(const u_char* p, QString& str);//UDOЭ�����
private:
	pcap_if_t *alldevs_;
	pcap_if_t *device_;//�豸����
	int devcount_; // ��������
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 g_ipaddress_, g_ipmask_;
	QVector<DEVInfo> DEVList;
	QQueue<m_StrDispalayinfo> qpack;
	QQueue<m_StrDispalayinfo> qpackAfter;
	void comboBoxInit();
	bool ok;
private:
	//bool setDevsFilter(const char *szFilter);					// �Ե�ǰ���豸���ù�����
	//void adjustwidget(); ///��������
public:
	QTimer *timer_;
	std::string filterString_;			// �����������ַ���
	QMap<int, int> g_nLenPktDataMap_;
	QMap<int, const u_char*> g_nArraymap_;
	QMap<int, QString> g_info;
};
