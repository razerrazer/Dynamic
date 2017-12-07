// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Copyright (c) 2009-2017 The Syscoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIGNRAWTXDIALOG_H
#define SIGNRAWTXDIALOG_H

#include <QDialog>

namespace Ui {
    class SignRawTxDialog;
}

/** Dialog for editing an address and associated information.
 */
class SignRawTxDialog : public QDialog
{
    Q_OBJECT

public:

    explicit SignRawTxDialog(QWidget *parent = 0);
    ~SignRawTxDialog();
private:
	bool saveCurrentRow();
	Ui::SignRawTxDialog *ui;
	void setRawTxEdit();
	void setRawIdentTxEdit();

public Q_SLOTS:
    void on_okButton_clicked();
	void on_cancelButton_clicked();
	void rawTxChanged();
};

#endif // SIGNRAWTXDIALOG_H
