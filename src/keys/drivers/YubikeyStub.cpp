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

Yubikey::Yubikey() : m_yk_void(NULL), m_ykds_void(NULL)
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
    return false;
}

bool Yubikey::deinit()
{
    return false;
}

void Yubikey::detect()
{
}

bool Yubikey::getSerial(unsigned int& serial) const
{
    Q_UNUSED(serial);

    return false;
}

Yubikey::ChallengeResult Yubikey::challenge(int slot, bool mayBlock,
                                            const QByteArray& chal,
                                            QByteArray& resp) const
{
    Q_UNUSED(slot);
    Q_UNUSED(mayBlock);
    Q_UNUSED(chal);
    Q_UNUSED(resp);

    return ERROR;
}
