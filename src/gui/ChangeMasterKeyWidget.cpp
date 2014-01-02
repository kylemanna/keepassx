/*
 *  Copyright (C) 2012 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ChangeMasterKeyWidget.h"
#include "ui_ChangeMasterKeyWidget.h"

#include "keys/FileKey.h"
#include "keys/PasswordKey.h"
#include "keys/YkChallengeResponseKey.h"
#include "gui/FileDialog.h"
#include "gui/MessageBox.h"
#include "crypto/Random.h"

ChangeMasterKeyWidget::ChangeMasterKeyWidget(QWidget* parent)
    : DialogyWidget(parent)
    , m_ui(new Ui::ChangeMasterKeyWidget())
{
    m_ui->setupUi(this);

    connect(m_ui->buttonBox, SIGNAL(accepted()), SLOT(generateKey()));
    connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(reject()));
    connect(m_ui->togglePasswordButton, SIGNAL(toggled(bool)), SLOT(togglePassword(bool)));
    connect(m_ui->createKeyFileButton, SIGNAL(clicked()), SLOT(createKeyFile()));
    connect(m_ui->browseKeyFileButton, SIGNAL(clicked()), SLOT(browseKeyFile()));
}

ChangeMasterKeyWidget::~ChangeMasterKeyWidget()
{
}

void ChangeMasterKeyWidget::togglePassword(bool checked)
{
    m_ui->enterPasswordEdit->setEchoMode(checked ? QLineEdit::Password : QLineEdit::Normal);
    m_ui->repeatPasswordEdit->setEchoMode(checked ? QLineEdit::Password : QLineEdit::Normal);
}

void ChangeMasterKeyWidget::createKeyFile()
{
    QString filters = QString("%1 (*.key);;%2 (*)").arg(tr("Key files"), tr("All files"));
    QString fileName = fileDialog()->getSaveFileName(this, tr("Create Key File..."), QString(), filters);

    if (!fileName.isEmpty()) {
        QString errorMsg;
        bool created = FileKey::create(fileName, &errorMsg);
        if (!created) {
            MessageBox::warning(this, tr("Error"), tr("Unable to create Key File : ") + errorMsg);
        }
        else {
            m_ui->keyFileCombo->setEditText(fileName);
        }
    }
}

void ChangeMasterKeyWidget::browseKeyFile()
{
    QString filters = QString("%1 (*.key);;%2 (*)").arg(tr("Key files"), tr("All files"));
    QString fileName = fileDialog()->getOpenFileName(this, tr("Select a key file"), QString(), filters);

    if (!fileName.isEmpty()) {
        m_ui->keyFileCombo->setEditText(fileName);
    }
}

void ChangeMasterKeyWidget::clearForms()
{
    m_key.clear();

    m_ui->passwordGroup->setChecked(true);
    m_ui->enterPasswordEdit->setText("");
    m_ui->repeatPasswordEdit->setText("");
    m_ui->keyFileGroup->setChecked(false);
    m_ui->togglePasswordButton->setChecked(true);
    // TODO: clear m_ui->keyFileCombo

    m_ui->challengeResponseGroup->setChecked(false);
    m_ui->challengeResponseCombo->clear();

    /* Code is duplicated in DatabaseOpenWidget.cpp */
    if (yubikey()->init()) {
        QString fmt("Yubikey[%1] Challenge Response - Slot %2 - %3");

        for (int i = 1; i < 3; i++) {
            Yubikey::ChallengeResult result;
            QByteArray rand = randomGen()->randomArray(8);
            QByteArray resp;

            result = yubikey()->challenge(i, false, rand, resp);

            if (result != Yubikey::ERROR) {
                const char *conf;
                conf = (result == Yubikey::WOULDBLOCK) ? "Press" : "Passive";

                QString s = fmt.arg(QString::number(yubikey()->getSerial()),
                                    QString::number(i),
                                    conf);

                m_ui->challengeResponseCombo->addItem(s, QVariant(i));
            }
        }
    }

    m_ui->enterPasswordEdit->setFocus();
}

CompositeKey ChangeMasterKeyWidget::newMasterKey()
{
    return m_key;
}

QLabel* ChangeMasterKeyWidget::headlineLabel()
{
    return m_ui->headlineLabel;
}

void ChangeMasterKeyWidget::generateKey()
{
    m_key.clear();

    if (m_ui->passwordGroup->isChecked()) {
        if (m_ui->enterPasswordEdit->text() == m_ui->repeatPasswordEdit->text()) {
            if (m_ui->enterPasswordEdit->text().isEmpty()) {
                if (MessageBox::question(this, tr("Question"),
                                         tr("Do you really want to use an empty string as password?"),
                                         QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
                    return;
                }
            }
            m_key.addKey(PasswordKey(m_ui->enterPasswordEdit->text()));
        }
        else {
            MessageBox::warning(this, tr("Error"), tr("Different passwords supplied."));
            m_ui->enterPasswordEdit->setText("");
            m_ui->repeatPasswordEdit->setText("");
            return;
        }
    }
    if (m_ui->keyFileGroup->isChecked()) {
        FileKey fileKey;
        QString errorMsg;
        if (!fileKey.load(m_ui->keyFileCombo->currentText(), &errorMsg)) {
            // TODO: error handling
        }
        m_key.addKey(fileKey);
    }

    if (m_ui->challengeResponseGroup->isChecked()) {
        int i = m_ui->challengeResponseCombo->currentIndex();
        i = m_ui->challengeResponseCombo->itemData(i).toInt();
        YkChallengeResponseKey key(i);

        printf("Trying to add challenge response key %d\n", i);

        m_key.addChallengeResponseKey(key);
    }

    Q_EMIT editFinished(true);
}


void ChangeMasterKeyWidget::reject()
{
    Q_EMIT editFinished(false);
}
