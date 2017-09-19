#include "winpcap.h"
#include <QtWidgets/QApplication>
#include <QDebug>


int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	winpcap w;
	w.show();
	return a.exec();
}
