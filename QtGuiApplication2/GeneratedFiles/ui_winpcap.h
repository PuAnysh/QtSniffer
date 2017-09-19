/********************************************************************************
** Form generated from reading UI file 'winpcap.ui'
**
** Created by: Qt User Interface Compiler version 5.8.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WINPCAP_H
#define UI_WINPCAP_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_winpcapClass
{
public:
    QAction *捕获过滤;
    QWidget *centralWidget;
    QWidget *layoutWidget;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QSpacerItem *horizontalSpacer;
    QPushButton *serchButton;
    QListView *listView;
    QTableWidget *tableWidget;
    QPushButton *runButton;
    QWidget *layoutWidget1;
    QVBoxLayout *verticalLayout;
    QLabel *label_3;
    QTextEdit *textEdit;
    QGroupBox *groupBox;
    QWidget *layoutWidget2;
    QVBoxLayout *verticalLayout_2;
    QLabel *label_2;
    QTextEdit *addrEdit;
    QWidget *layoutWidget3;
    QVBoxLayout *verticalLayout_3;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label_4;
    QComboBox *filterComboBox;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label_5;
    QSpinBox *limitSpinBox;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;
    QMenuBar *menuBar;
    QMenu *menu;
    QMenu *menu_2;

    void setupUi(QMainWindow *winpcapClass)
    {
        if (winpcapClass->objectName().isEmpty())
            winpcapClass->setObjectName(QStringLiteral("winpcapClass"));
        winpcapClass->resize(574, 613);
        捕获过滤 = new QAction(winpcapClass);
        捕获过滤->setObjectName(QString::fromUtf8("\346\215\225\350\216\267\350\277\207\346\273\244"));
        捕获过滤->setCheckable(true);
        QIcon icon;
        QString iconThemeName = QString::fromUtf8("\346\215\225\350\216\267\350\277\207\346\273\244");
        if (QIcon::hasThemeIcon(iconThemeName)) {
            icon = QIcon::fromTheme(iconThemeName);
        } else {
            icon.addFile(QStringLiteral(""), QSize(), QIcon::Normal, QIcon::Off);
        }
        捕获过滤->setIcon(icon);
        centralWidget = new QWidget(winpcapClass);
        centralWidget->setObjectName(QStringLiteral("centralWidget"));
        layoutWidget = new QWidget(centralWidget);
        layoutWidget->setObjectName(QStringLiteral("layoutWidget"));
        layoutWidget->setGeometry(QRect(250, 210, 141, 51));
        horizontalLayout = new QHBoxLayout(layoutWidget);
        horizontalLayout->setSpacing(6);
        horizontalLayout->setContentsMargins(11, 11, 11, 11);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        horizontalLayout->setContentsMargins(0, 0, 0, 0);
        label = new QLabel(layoutWidget);
        label->setObjectName(QStringLiteral("label"));

        horizontalLayout->addWidget(label);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        serchButton = new QPushButton(layoutWidget);
        serchButton->setObjectName(QStringLiteral("serchButton"));

        horizontalLayout->addWidget(serchButton);

        listView = new QListView(centralWidget);
        listView->setObjectName(QStringLiteral("listView"));
        listView->setGeometry(QRect(10, 200, 231, 101));
        tableWidget = new QTableWidget(centralWidget);
        if (tableWidget->columnCount() < 9)
            tableWidget->setColumnCount(9);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(2, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(3, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(4, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(5, __qtablewidgetitem5);
        QTableWidgetItem *__qtablewidgetitem6 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(6, __qtablewidgetitem6);
        QTableWidgetItem *__qtablewidgetitem7 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(7, __qtablewidgetitem7);
        QTableWidgetItem *__qtablewidgetitem8 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(8, __qtablewidgetitem8);
        tableWidget->setObjectName(QStringLiteral("tableWidget"));
        tableWidget->setGeometry(QRect(20, 10, 531, 181));
        runButton = new QPushButton(centralWidget);
        runButton->setObjectName(QStringLiteral("runButton"));
        runButton->setGeometry(QRect(440, 210, 71, 51));
        layoutWidget1 = new QWidget(centralWidget);
        layoutWidget1->setObjectName(QStringLiteral("layoutWidget1"));
        layoutWidget1->setGeometry(QRect(250, 270, 258, 212));
        verticalLayout = new QVBoxLayout(layoutWidget1);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        label_3 = new QLabel(layoutWidget1);
        label_3->setObjectName(QStringLiteral("label_3"));

        verticalLayout->addWidget(label_3);

        textEdit = new QTextEdit(layoutWidget1);
        textEdit->setObjectName(QStringLiteral("textEdit"));

        verticalLayout->addWidget(textEdit);

        groupBox = new QGroupBox(centralWidget);
        groupBox->setObjectName(QStringLiteral("groupBox"));
        groupBox->setGeometry(QRect(10, 440, 241, 101));
        layoutWidget2 = new QWidget(centralWidget);
        layoutWidget2->setObjectName(QStringLiteral("layoutWidget2"));
        layoutWidget2->setGeometry(QRect(10, 310, 221, 91));
        verticalLayout_2 = new QVBoxLayout(layoutWidget2);
        verticalLayout_2->setSpacing(6);
        verticalLayout_2->setContentsMargins(11, 11, 11, 11);
        verticalLayout_2->setObjectName(QStringLiteral("verticalLayout_2"));
        verticalLayout_2->setContentsMargins(0, 0, 0, 0);
        label_2 = new QLabel(layoutWidget2);
        label_2->setObjectName(QStringLiteral("label_2"));

        verticalLayout_2->addWidget(label_2);

        addrEdit = new QTextEdit(layoutWidget2);
        addrEdit->setObjectName(QStringLiteral("addrEdit"));

        verticalLayout_2->addWidget(addrEdit);

        layoutWidget3 = new QWidget(centralWidget);
        layoutWidget3->setObjectName(QStringLiteral("layoutWidget3"));
        layoutWidget3->setGeometry(QRect(20, 461, 221, 71));
        verticalLayout_3 = new QVBoxLayout(layoutWidget3);
        verticalLayout_3->setSpacing(6);
        verticalLayout_3->setContentsMargins(11, 11, 11, 11);
        verticalLayout_3->setObjectName(QStringLiteral("verticalLayout_3"));
        verticalLayout_3->setContentsMargins(0, 0, 0, 0);
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setSpacing(6);
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        label_4 = new QLabel(layoutWidget3);
        label_4->setObjectName(QStringLiteral("label_4"));

        horizontalLayout_2->addWidget(label_4);

        filterComboBox = new QComboBox(layoutWidget3);
        filterComboBox->setObjectName(QStringLiteral("filterComboBox"));
        filterComboBox->setEditable(true);

        horizontalLayout_2->addWidget(filterComboBox);


        verticalLayout_3->addLayout(horizontalLayout_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setSpacing(6);
        horizontalLayout_3->setObjectName(QStringLiteral("horizontalLayout_3"));
        label_5 = new QLabel(layoutWidget3);
        label_5->setObjectName(QStringLiteral("label_5"));

        horizontalLayout_3->addWidget(label_5);

        limitSpinBox = new QSpinBox(layoutWidget3);
        limitSpinBox->setObjectName(QStringLiteral("limitSpinBox"));

        horizontalLayout_3->addWidget(limitSpinBox);


        verticalLayout_3->addLayout(horizontalLayout_3);

        winpcapClass->setCentralWidget(centralWidget);
        layoutWidget->raise();
        layoutWidget->raise();
        layoutWidget->raise();
        layoutWidget->raise();
        listView->raise();
        tableWidget->raise();
        runButton->raise();
        groupBox->raise();
        mainToolBar = new QToolBar(winpcapClass);
        mainToolBar->setObjectName(QStringLiteral("mainToolBar"));
        winpcapClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(winpcapClass);
        statusBar->setObjectName(QStringLiteral("statusBar"));
        winpcapClass->setStatusBar(statusBar);
        menuBar = new QMenuBar(winpcapClass);
        menuBar->setObjectName(QStringLiteral("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 574, 23));
        menu = new QMenu(menuBar);
        menu->setObjectName(QStringLiteral("menu"));
        menu_2 = new QMenu(menuBar);
        menu_2->setObjectName(QStringLiteral("menu_2"));
        winpcapClass->setMenuBar(menuBar);

        menuBar->addAction(menu->menuAction());
        menuBar->addAction(menu_2->menuAction());

        retranslateUi(winpcapClass);
        QObject::connect(serchButton, SIGNAL(clicked()), winpcapClass, SLOT(serchButton_Click()));

        QMetaObject::connectSlotsByName(winpcapClass);
    } // setupUi

    void retranslateUi(QMainWindow *winpcapClass)
    {
        winpcapClass->setWindowTitle(QApplication::translate("winpcapClass", "winpcap", Q_NULLPTR));
        捕获过滤->setText(QApplication::translate("winpcapClass", "\346\215\225\350\216\267\350\277\207\346\273\244", Q_NULLPTR));
        label->setText(QApplication::translate("winpcapClass", "\347\275\221\345\215\241\345\210\227\350\241\250", Q_NULLPTR));
        serchButton->setText(QApplication::translate("winpcapClass", "\346\220\234\347\264\242", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem = tableWidget->horizontalHeaderItem(1);
        ___qtablewidgetitem->setText(QApplication::translate("winpcapClass", "\346\235\245\346\272\220ip", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem1 = tableWidget->horizontalHeaderItem(2);
        ___qtablewidgetitem1->setText(QApplication::translate("winpcapClass", "\346\272\220Mac", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem2 = tableWidget->horizontalHeaderItem(3);
        ___qtablewidgetitem2->setText(QApplication::translate("winpcapClass", "\347\233\256\346\240\207ip", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem3 = tableWidget->horizontalHeaderItem(4);
        ___qtablewidgetitem3->setText(QApplication::translate("winpcapClass", "\347\233\256\346\240\207Mac", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem4 = tableWidget->horizontalHeaderItem(5);
        ___qtablewidgetitem4->setText(QApplication::translate("winpcapClass", "\345\215\217\350\256\256", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem5 = tableWidget->horizontalHeaderItem(6);
        ___qtablewidgetitem5->setText(QApplication::translate("winpcapClass", "\345\214\205\351\225\277", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem6 = tableWidget->horizontalHeaderItem(7);
        ___qtablewidgetitem6->setText(QApplication::translate("winpcapClass", "\346\272\220\347\253\257\345\217\243", Q_NULLPTR));
        QTableWidgetItem *___qtablewidgetitem7 = tableWidget->horizontalHeaderItem(8);
        ___qtablewidgetitem7->setText(QApplication::translate("winpcapClass", "\347\233\256\346\240\207\347\253\257\345\217\243", Q_NULLPTR));
        runButton->setText(QApplication::translate("winpcapClass", "START", Q_NULLPTR));
        label_3->setText(QApplication::translate("winpcapClass", "\346\225\260\346\215\256\345\214\205\350\257\246\346\203\205\357\274\232", Q_NULLPTR));
        groupBox->setTitle(QApplication::translate("winpcapClass", "\346\215\225\350\216\267\350\277\207\346\273\244\350\256\276\347\275\256", Q_NULLPTR));
        label_2->setText(QApplication::translate("winpcapClass", "\347\275\221\345\215\241\350\257\246\347\273\206\344\277\241\346\201\257\346\230\276\347\244\272\357\274\232", Q_NULLPTR));
        label_4->setText(QApplication::translate("winpcapClass", "\351\200\211\346\213\251\345\215\217\350\256\256", Q_NULLPTR));
        filterComboBox->setCurrentText(QString());
        label_5->setText(QApplication::translate("winpcapClass", "\346\234\200\345\244\247\345\214\205\350\256\276\347\275\256", Q_NULLPTR));
        menu->setTitle(QApplication::translate("winpcapClass", "\350\256\276\347\275\256", Q_NULLPTR));
        menu_2->setTitle(QApplication::translate("winpcapClass", "\350\277\207\346\273\244", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class winpcapClass: public Ui_winpcapClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WINPCAP_H
