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
	// ������ʾ�����б�
	QStringList listDevice_;
	QStringListModel *model_;
	PcapThread *pcapthread_;

private slots:
	void printTableInfo(m_StrDispalayinfo );  // ��ӡץ����Ϣ
	void serchButton_Click();//���������б�
	void OnListItemClicked(QModelIndex index);// ��ӡ������Ϣ
	void runclicked();// �߳���������
	void getTableItem(int row ,int);// ����ͨ����굥���õ��ĵ�Ԫ��ָ�룬���������������Ϣ
	void setFilterString(int index); ///���ò������ַ�

private:
	pcap_if_t *alldevs_;
	pcap_if_t *device_;//�豸����
	int devcount_  ; // ��������
    char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 g_ipaddress_,g_ipmask_;


private:
	bool setDevsFilter(const char *szFilter);					// �Ե�ǰ���豸���ù�����
	void adjustwidget() ; ///��������
public:
	QTimer *timer_;
	std::string filterString_;			// �����������ַ���
	QMap<int,int> g_nLenPktDataMap_;
	QMap<int, const u_char*> g_nArraymap_;
};

#endif // WINPCAP_H
