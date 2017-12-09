// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Copyright (c) 2009-2017 The Syscoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CERTVIEW_H
#define CERTVIEW_H

#include <QStackedWidget>

class DynamicGUI;
class ClientModel;
class WalletModel;
class MyCertListPage;
class CertListPage;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QObject;
class QWidget;
class QLabel;
class QModelIndex;
class QTabWidget;
class QStackedWidget;
class QAction;
QT_END_NAMESPACE

/*
  CertView class. This class represents the view to the Dynamic certs
  
*/
class CertView: public QObject
 {
     Q_OBJECT

public:
    explicit CertView(const PlatformStyle *platformStyle, QStackedWidget *parent);
    ~CertView();

    void setDynamicGUI(DynamicGUI *gui);
    /** Set the client model.
        The client model represents the part of the core that communicates with the P2P network, and is wallet-agnostic.
    */
    void setClientModel(ClientModel *clientModel);
    /** Set the wallet model.
        The wallet model represents a Dynamic wallet, and offers access to the list of transactions, address book and sending
        functionality.
    */
    void setWalletModel(WalletModel *walletModel);

private:
    DynamicGUI *gui;
    ClientModel *clientModel;
    WalletModel *walletModel;

    QTabWidget *tabWidget;
    MyCertListPage *myCertListPage;
    CertListPage *certListPage;

public:
    /** Switch to offer page */
    void gotoCertListPage();

Q_SIGNALS:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
};

#endif // CERTVIEW_H
