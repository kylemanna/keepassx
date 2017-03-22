/*
*  Copyright (C) 2015 Pedro Alves <devel@pgalves.com>
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


#include <QCryptographicHash>

#include "keys/HmacSha1ChallengeResponseKey.h"

#include <QDebug>


HmacSha1ChallengeResponseKey::HmacSha1ChallengeResponseKey(QByteArray& hmackey, YkHmacMode mode)
{
    m_hmackey = hmackey;
    m_hmacmode = mode;
}

QByteArray HmacSha1ChallengeResponseKey::rawKey() const
{
    return m_key;
}

HmacSha1ChallengeResponseKey* HmacSha1ChallengeResponseKey::clone() const
{
    return new HmacSha1ChallengeResponseKey(*this);
}

bool HmacSha1ChallengeResponseKey::challenge(const QByteArray& chal)
{
    /* The Yubikey configured in HMAC variable input mode
     * discards the PKCS7 padding of the challenge so do not
     * pad the challenge */
    if (m_hmacmode == VARIABLE) {
        m_key = hmacSha1(chal);
        return true;
    }

    /* The Yubikey configured in HMAC Fixed 64 bytes input mode
     * needs to be padded with PKCS7 like it was done when saving the
     * the database with the Yubikey challenge */
    QByteArray paddedChal = chal;

    const int padLen = 64 - paddedChal.size();
    if (padLen > 0) {
        paddedChal.append(QByteArray(padLen, padLen));
    }

    m_key = hmacSha1(paddedChal);

    return true;
}

/* HMAC code from: http://qt-project.org/wiki/HMAC-SHA1 */
QByteArray HmacSha1ChallengeResponseKey::hmacSha1(const QByteArray& chal)
{
    int blockSize = 64; // HMAC-SHA-1 block size, defined in SHA-1 standard
    QByteArray paddedKey = m_hmackey;

    if (m_hmackey.length() > blockSize) { // if key is longer than block size (64), reduce key length with SHA-1 compression
        paddedKey = QCryptographicHash::hash(m_hmackey, QCryptographicHash::Sha1);
    }

    QByteArray innerPadding(blockSize, char(0x36)); // initialize inner padding with char "6"
    QByteArray outerPadding(blockSize, char(0x5c)); // initialize outer padding with char "\"

    for (int i = 0; i < m_hmackey.length(); i++) {
        innerPadding[i] = innerPadding[i] ^ paddedKey.at(i); // XOR operation between every byte in key and innerpadding, of key length
        outerPadding[i] = outerPadding[i] ^ paddedKey.at(i); // XOR operation between every byte in key and outerpadding, of key length
    }

    // result = hash ( outerPadding CONCAT hash ( innerPadding CONCAT baseString ) )
    QByteArray total = outerPadding;
    QByteArray part = innerPadding;

    part.append(chal);
    total.append(QCryptographicHash::hash(part, QCryptographicHash::Sha1));
    QByteArray hashed = QCryptographicHash::hash(total, QCryptographicHash::Sha1);

    return hashed;
}
