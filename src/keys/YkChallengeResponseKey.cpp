/*
*  Copyright (C) 2011 Felix Geyer <debfx@fobos.de>
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


#include <QFile>
#include <QXmlStreamReader>

#include <yubikey.h>
#include <ykdef.h>
#include <ykcore.h>
#include <ykstatus.h>
#include <ykpers-version.h>

#include "core/Tools.h"
#include "crypto/CryptoHash.h"
#include "crypto/Random.h"

#include "keys/YkChallengeResponseKey.h"

YkChallengeResponseKey::YkChallengeResponseKey(int slot)
: m_slot(slot)
{
}

QByteArray YkChallengeResponseKey::rawKey() const
{
    return m_key;
}

YkChallengeResponseKey* YkChallengeResponseKey::clone() const
{
    return new YkChallengeResponseKey(*this);
}

static inline QString printByteArray(const QByteArray& a)
{
    QString s;
    for (int i = 0; i < a.size(); i++)
        s.append(QString::number(a[i] & 0xff, 16).rightJustified(2, '0'));
    return s;
}

bool YkChallengeResponseKey::challenge(const QByteArray& challenge)
{
    YK_KEY *yk = NULL;
    m_slot = 2;
    int yk_cmd = (m_slot == 1) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_HMAC2;

    printf("%s(%d) called, s = %s\n", __func__, m_slot, printByteArray(challenge).toLocal8Bit().data());

    if (!yk_init()) {
        printf("%s() unable to init yk\n", __func__);
        return false;
    }

    if (!(yk = yk_open_first_key())) {
        printf("%s() unable to open first yk\n", __func__);
        return false;
    }

    char response[64];
    memset(response, 0, sizeof(response));

    if(!yk_challenge_response(yk, yk_cmd, true,
            challenge.size(), (const unsigned char*)(challenge.constData()),
            sizeof(response), (unsigned char*)response)) {
        printf("%s() failed chal resp yk\n", __func__);
        return false;
    }

    const int expected_bytes = 20;
    m_key.clear();
    m_key.append(response, expected_bytes);

    printf("%s(%d) called, s = %s\n", __func__, m_slot, printByteArray(m_key).toLocal8Bit().data());

    return true;
}
