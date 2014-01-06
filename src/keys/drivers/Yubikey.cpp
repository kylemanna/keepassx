/*
*  Copyright (C) 2014 Kyle Manna <kyle@kylemanna.com>
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

#include <stdio.h>

#include "core/Global.h"
#include "crypto/Random.h"

#include "Yubikey.h"

Yubikey::Yubikey()
{
}

Yubikey* Yubikey::m_instance(Q_NULLPTR);

Yubikey* Yubikey::instance()
{
    if (!m_instance) {
        m_instance = new Yubikey();
    }

    return m_instance;
}

bool Yubikey::init()
{
    if (!yk_init()) {
        fprintf(stderr, "%s() unable to init yk\n", __func__);
        return false;
    }

    /* Todo: scale to multiple keys */
    m_yk = yk_open_first_key();
    if (!m_yk) {
        fprintf(stderr, "%s() unable to open first yk\n", __func__);
        return false;
    }

    if (!yk_get_serial(m_yk, 1, 0, &m_serial)) {
        fprintf(stderr, "%s() failed to read serial\n", __func__);
        return false;
    }


    return true;
}

/* TODO: this should probably be replaced with something using signals/slots
 * and is thread safe.  addComboBoxItems() probably isn't thread safe if called
 * from a different thread
 */
unsigned int Yubikey::addComboBoxItems(QComboBox* combo)
{
    /* Code is duplicated in DatabaseOpenWidget.cpp */
    if (init()) {
        QString fmt("Yubikey[%1] Challenge Response - Slot %2 - %3");

        for (int i = 1; i < 3; i++) {
            Yubikey::ChallengeResult result;
            QByteArray rand = randomGen()->randomArray(8);
            QByteArray resp;

            result = challenge(i, false, rand, resp);

            if (result != Yubikey::ERROR) {
                const char *conf;
                conf = (result == Yubikey::WOULDBLOCK) ? "Press" : "Passive";

                QString s = fmt.arg(QString::number(getSerial()),
                                    QString::number(i),
                                    conf);

                combo->addItem(s, QVariant(i));
            }
        }
    }
    return 0;
}

unsigned int Yubikey::getSerial() const
{
    return m_serial;
}

static void report_yk_error(void)
{
    if (yk_errno) {
        if (yk_errno == YK_EUSBERR) {
            fprintf(stderr, "USB error: %s\n",
                    yk_usb_strerror());
        } else {
            fprintf(stderr, "Yubikey core error: %s\n",
                    yk_strerror(yk_errno));
        }
    }
}

static inline QString printByteArray(const QByteArray& a)
{
    QString s;
    for (int i = 0; i < a.size(); i++)
        s.append(QString::number(a[i] & 0xff, 16).rightJustified(2, '0'));
    return s;
}


Yubikey::ChallengeResult Yubikey::challenge(int slot, bool mayBlock,
                                            const QByteArray& chal,
                                            QByteArray& resp) const
{
    int yk_cmd = (slot == 1) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_HMAC2;

    /* yk_challenge_response() insists on 64 byte response buffer */
    resp.resize(64);

    const unsigned char *c;
    unsigned char *r;
    c = reinterpret_cast<const unsigned char*>(chal.constData());
    r = reinterpret_cast<unsigned char*>(resp.data());

    fprintf(stderr, "%s(%d) c = %s\n", __func__, slot,
            printByteArray(chal).toLocal8Bit().data());

    int ret = yk_challenge_response(m_yk, yk_cmd, mayBlock,
                                    chal.size(), c,
                                    resp.size(), r);

    if(!ret) {
        if (yk_errno == YK_EWOULDBLOCK) {
            return WOULDBLOCK;
        } else {
            report_yk_error();
            return ERROR;
        }
    }

    /* Actual HMAC-SHA1 response is only 20 bytes */
    resp.resize(20);

    fprintf(stderr, "%s(%d) r = %s, ret = %d\n", __func__, slot,
            printByteArray(resp).toLocal8Bit().data(), ret);

    return SUCCESS;
}
