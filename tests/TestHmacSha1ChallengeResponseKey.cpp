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

#include "TestHmacSha1ChallengeResponseKey.h"

#include <QTest>

#include "config-keepassx-tests.h"
#include "tests.h"
#include "core/Database.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"
#include "format/KeePass2Reader.h"
#include "keys/HmacSha1ChallengeResponseKey.h"

QTEST_GUILESS_MAIN(TestHmacChallengeResponse)

void TestHmacChallengeResponse::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestHmacChallengeResponse::testHmacSha1()
{
    /* Set NIST FIPS 198 A.2 test vector as HMAC key */
    QByteArray secretkey = QByteArray::fromHex("303132333435363738393a3b3c3d3e3f40414243");
    /* Set NIST 198 challenge */
    QByteArray chal = QByteArray::fromHex("53616d706c65202332");
    const QByteArray expected(QByteArray::fromHex("0922d3405faa3d194f82a45830737d5cc6c75d24"));
    /* The VARIABLE and FIXED64 moded only have influence on the challenge size (padded or non padded)
     * not in the HMCA calculation, no need to test both here. Using variable mode as the test
     * challenge < 64 bytes */
    HmacSha1ChallengeResponseKey hmackey(secretkey, HmacSha1ChallengeResponseKey::VARIABLE);

    QCOMPARE(hmackey.hmacSha1(chal), expected);
}

void TestHmacChallengeResponse::testOpenYkVariableInput()
{
    QString filename = QString(KEEPASSX_TEST_DATA_DIR).append("/YkVariableHmacChal.kdbx");
    CompositeKey key;
    QByteArray hmacsecretkey = QByteArray::fromHex("303132333435363738393a3b3c3d3e3f40414243");
    key.addChallengeResponseKey(HmacSha1ChallengeResponseKey(hmacsecretkey, HmacSha1ChallengeResponseKey::VARIABLE));
    KeePass2Reader reader;
    Database* db = reader.readDatabase(filename, key);
    QVERIFY(db);
    QVERIFY(!reader.hasError());
    QCOMPARE(db->metadata()->name(), QString("HmacVariableInput"));

    delete db;
}

void TestHmacChallengeResponse::testOpenYkFixed64Input()
{
    QString filename = QString(KEEPASSX_TEST_DATA_DIR).append("/YkFixed64HmacChal.kdbx");
    CompositeKey key;
    QByteArray hmacsecretkey = QByteArray::fromHex("303132333435363738393a3b3c3d3e3f40414243");
    key.addChallengeResponseKey(HmacSha1ChallengeResponseKey(hmacsecretkey, HmacSha1ChallengeResponseKey::FIXED64));
    KeePass2Reader reader;
    Database* db = reader.readDatabase(filename, key);
    QVERIFY(db);
    QVERIFY(!reader.hasError());
    QCOMPARE(db->metadata()->name(), QString("HmacFixed64Input"));

    delete db;
}
