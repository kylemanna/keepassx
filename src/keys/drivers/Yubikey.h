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

#ifndef KEEPASSX_YUBIKEY_H
#define KEEPASSX_YUBIKEY_H

#include <QObject>
#include <QComboBox>

#include <yubikey.h>
#include <ykcore.h>
#include <ykdef.h>
#include <ykstatus.h>
#include <ykpers-version.h>

/**
 * Singleton class to manage the interface to the hardware
 */
class Yubikey
{
public:
    enum ChallengeResult { ERROR = -1, SUCCESS = 0, WOULDBLOCK };

    static Yubikey* instance();

    bool init();

    ChallengeResult challenge(int slot, bool mayBlock,
                              const QByteArray& chal,
                              QByteArray& resp) const;

    unsigned int getSerial() const;
    unsigned int addComboBoxItems(QComboBox *combo);

private:
    explicit Yubikey();

    static Yubikey* m_instance;
    YK_KEY *m_yk;
    unsigned int m_serial;

    Q_DISABLE_COPY(Yubikey)
};

inline Yubikey* yubikey() {
    return Yubikey::instance();
}

#endif // KEEPASSX_YUBIKEY_H
