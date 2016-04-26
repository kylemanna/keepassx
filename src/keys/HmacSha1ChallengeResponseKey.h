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

#ifndef KEEPASSX_HMACSHA1_CHALLENGERESPONSEKEY_H
#define KEEPASSX_HMACSHA1_CHALLENGERESPONSEKEY_H

#include "core/Global.h"
#include "keys/ChallengeResponseKey.h"

class HmacSha1ChallengeResponseKey : public ChallengeResponseKey
{
public:
    enum YkHmacMode { VARIABLE, FIXED64};

    HmacSha1ChallengeResponseKey(QByteArray& key, YkHmacMode mode);

    QByteArray rawKey() const;
    HmacSha1ChallengeResponseKey* clone() const;
    bool challenge(const QByteArray& chal);
    bool challenge(const QByteArray& chal, YkHmacMode mode);
    QByteArray hmacSha1(const QByteArray& chal);

private:
    QByteArray m_key;
    QByteArray m_hmackey;
    YkHmacMode m_hmacmode;
};

#endif // KEEPASSX_HMACSHA1_CHALLENGERESPONSEKEY_H
