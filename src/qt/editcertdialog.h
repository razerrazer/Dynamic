// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Copyright (c) 2009-2017 The Syscoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDITCERTDIALOG_H
#define EDITCERTDIALOG_H

#include <QDialog>

namespace Ui {
    class EditCertDialog;
}
class CertTableModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
class QStandardItemModel;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditCertDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewCert,
        EditCert,
		TransferCert
    };

    explicit EditCertDialog(Mode mode, QWidget *parent = 0);
    ~EditCertDialog();

    void setModel(WalletModel*,CertTableModel *model);
    void loadRow(int row);
    void addParentItem(QStandardItemModel * model, const QString& text, const QVariant& data );
    void addChildItem( QStandardItemModel * model, const QString& text, const QVariant& data );
	void setCertNotSafeBecauseOfAlias(const QString &alias);
	void resetSafeSearch();
    QString getCert() const;
    void setCert(const QString &cert);

public Q_SLOTS:
    void accept();
	void aliasChanged(const QString& text);

private:
    bool saveCurrentRow();
	void loadAliases();
	void loadCategories();
    Ui::EditCertDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    CertTableModel *model;
	WalletModel* walletModel;
    QString cert;
	QString expiredStr;
};

#endif // EDITCERTDIALOG_H
