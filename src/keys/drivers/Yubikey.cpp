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

#include <ykcore.h>
#include <yubikey.h>
#include <ykdef.h>
#include <ykstatus.h>
#include <ykpers-version.h>

#include "Yubikey.h"

/* Cast the void pointer from the generalized class definition
 * to the proper pointer type from the now included system libraries
 */
#define m_yk (static_cast<YK_KEY*>(m_yk_void))

Yubikey::Yubikey() : m_yk_void(NULL)
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
    /* Already initalized */
    if (m_yk != NULL) {
        return true;
    }

    if (!yk_init()) {
        return false;
    }

    /* TODO: handle multiple attached hardware devices, currently own one */
    m_yk_void = static_cast<void *>(yk_open_first_key());
    if (m_yk == NULL) {
        return false;
    }

    return true;
}

void Yubikey::detect()
{
    if (init()) {

        for (int i = 1; i < 3; i++) {
            Yubikey::ChallengeResult result;
            QByteArray rand = randomGen()->randomArray(1);
            QByteArray resp;

            result = challenge(i, false, rand, resp);

            if (result != Yubikey::ERROR) {
                Q_EMIT detected(i, result == Yubikey::WOULDBLOCK ? true : false);
            }
        }
    }
}

bool Yubikey::getSerial(unsigned int& serial) const
{
    if (!yk_get_serial(m_yk, 1, 0, &serial)) {
        fprintf(stderr, "%s() failed to read serial\n", __func__);
        return false;
    }

    return true;
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
    QByteArray paddedChal = chal;

    /* yk_challenge_response() insists on 64 byte response buffer */
    resp.resize(64);

    /* The challenge sent to the yubikey should always be 64 bytes for
     * compatibility with all configurations.  Follow PKCS7 padding.
     *
     * There is some question whether or not 64 byte fixed length
     * configurations even work, some docs say avoid it.
     */
    const int padLen = 64 - paddedChal.size();
    if (padLen > 0) {
        paddedChal.append(QByteArray(padLen, padLen));
    }

    const unsigned char *c;
    unsigned char *r;
    c = reinterpret_cast<const unsigned char*>(paddedChal.constData());
    r = reinterpret_cast<unsigned char*>(resp.data());

#ifdef QT_DEBUG
    fprintf(stderr, "%s(%d) c = %s\n", __func__, slot,
            printByteArray(paddedChal).toLocal8Bit().data());
#endif

    int ret = yk_challenge_response(m_yk, yk_cmd, mayBlock,
                                    paddedChal.size(), c,
                                    resp.size(), r);

    if(!ret) {
        if (yk_errno == YK_EWOULDBLOCK) {
            return WOULDBLOCK;
        } else if (yk_errno == YK_ETIMEOUT) {
            return ERROR;
        } else if (yk_errno) {
            if (yk_errno == YK_EUSBERR) {
                fprintf(stderr, "USB error: %s\n", yk_usb_strerror());
            } else {
                fprintf(stderr, "Yubikey core error: %s\n", yk_strerror(yk_errno));
            }
            return ERROR;
        }
    }

    /* Actual HMAC-SHA1 response is only 20 bytes */
    resp.resize(20);

#ifdef QT_DEBUG
    fprintf(stderr, "%s(%d) r = %s, ret = %d\n", __func__, slot,
            printByteArray(resp).toLocal8Bit().data(), ret);
#endif

    return SUCCESS;
}
