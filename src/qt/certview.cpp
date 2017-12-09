// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Copyright (c) 2009-2017 The Syscoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "certview.h"
#include "dynamicgui.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "mycertlistpage.h"
#include "certlistpage.h"
#include "certtablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

CertView::CertView(const PlatformStyle *platformStyle, QStackedWidget *parent):
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    certListPage = new CertListPage(platformStyle);
    myCertListPage = new MyCertListPage(platformStyle);
	QString theme = GUIUtil::getThemeName();
	tabWidget->addTab(myCertListPage, tr("My Certificates"));
	tabWidget->addTab(certListPage, tr("Search"));
	tabWidget->setTabIcon(0, platformStyle->SingleColorIcon(":/icons/" + theme + "/cert"));
	tabWidget->setTabIcon(1, platformStyle->SingleColorIcon(":/icons/" + theme + "/search"));
	parent->addWidget(tabWidget);

}

CertView::~CertView()
{
}

void CertView::setDynamicGUI(DynamicGUI *gui)
{
    this->gui = gui;
}

void CertView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {
       
        certListPage->setOptionsModel(clientModel->getOptionsModel());
		myCertListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());

    }
}

void CertView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {

        certListPage->setModel(walletModel, walletModel->getCertTableModelAll());
		myCertListPage->setModel(walletModel, walletModel->getCertTableModelMine());

    }
}


void CertView::gotoCertListPage()
{
	tabWidget->setCurrentWidget(certListPage);
}

