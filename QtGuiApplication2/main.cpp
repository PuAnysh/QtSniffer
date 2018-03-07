#include <QtWidgets/QApplication>
#include <QDebug>
#include "QtGuiApplication2.h"

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QtGuiApplication2 w;
	//winpcap w;
	w.show();
	return a.exec();
}
