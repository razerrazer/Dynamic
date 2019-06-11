// Copyright (c) 2019 Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_QT_BDAPFEESPOPUP_H
#define DYNAMIC_QT_BDAPFEESPOPUP_H

#include "bdap/fees.h"
#include "bdappage.h"

#include <QDialog>
#include <QMessageBox>
#include <QObject>
#include <QPushButton>
#include <QTranslator>

bool bdapFeesPopup(QDialog *parentDialog, const opcodetype& opCodeAction, const opcodetype& opCodeObject, BDAP::ObjectType inputAccountType = BDAP::ObjectType::BDAP_USER, int32_t regMonths = DEFAULT_REGISTRATION_MONTHS);
bool bdapFeesPopup(BdapPage *parentDialog, const opcodetype& opCodeAction, const opcodetype& opCodeObject, BDAP::ObjectType inputAccountType = BDAP::ObjectType::BDAP_USER, int32_t regMonths = DEFAULT_REGISTRATION_MONTHS);

#endif // DYNAMIC_QT_BDAPFEESPOPUP_H