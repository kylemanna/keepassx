/*
 *  Copyright (C) 2014 Kyle Manna <kyle@kylemanna.com>
 *
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

#include "TestYubikeyChalResp.h"

#include <QTest>
#include <QtConcurrentRun>

#include "tests.h"
#include "keys/YkChallengeResponseKey.h"

QTEST_GUILESS_MAIN(TestYubikeyChalResp)

void TestYubikeyChalResp::initTestCase()
{
    m_detected = 0;
    m_key = NULL;
}

void TestYubikeyChalResp::cleanupTestCase()
{
    if (m_key)
        delete m_key;
}

void TestYubikeyChalResp::init()
{
    bool result = Yubikey::instance()->init();

    if (!result) {
        QSKIP("Unable to connect to Yubikey", SkipAll);
    }
}

void TestYubikeyChalResp::detectDevices()
{
    connect(Yubikey::instance(), SIGNAL(detected(int,bool)),
                                 SLOT(ykDetected(int,bool)),
                                 Qt::QueuedConnection);
    QtConcurrent::run(Yubikey::instance(), &Yubikey::detect);

    /* Need to wait for the hardware (that's hopefully plugged in)... */
    QTest::qWait(2000);
    QVERIFY2(m_detected > 0, "Is a Yubikey attached?");
}

void TestYubikeyChalResp::getSerial()
{
    unsigned int serial;
    QVERIFY(Yubikey::instance()->getSerial(serial));
}

void TestYubikeyChalResp::keyGetName()
{
    QVERIFY(m_key);
    QVERIFY(m_key->getName().length() > 0);
}

void TestYubikeyChalResp::keyIssueChallenge()
{
    QVERIFY(m_key);
    if (m_key->isBlocking()) {
        /* Testing active mode in unit tests is unreasonable */
        QSKIP("Yubikey not in passive mode", SkipSingle);
    }

    QByteArray ba("UnitTest");
    QVERIFY(m_key->challenge(ba));

    /* TODO Determine if it's reasonable to provide a fixed secret key for
     *      verification testing.  Obviously simple technically, but annoying
     *      if devs need to re-program their yubikeys or have a spare test key
     *      for unit tests to past.
     *
     *      Might be worth it for integrity verification though.
     */
}

void TestYubikeyChalResp::ykDetected(int slot, bool blocking)
{
    Q_UNUSED(blocking);

    if (slot > 0)
        m_detected++;

    /* Key used for later testing */
    if (!m_key)
        m_key = new YkChallengeResponseKey(slot, blocking);
}

void TestYubikeyChalResp::deinit()
{
    QVERIFY(Yubikey::instance()->deinit());
}
