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

#include <stdio.h>

#include <QCoreApplication>
#include <QFile>
#include <QStringList>
#include <QFileInfo>
#include <QTextStream>

#include "crypto/Crypto.h"
#include "core/Database.h"
#include "core/qcommandlineparser.h"
#include "core/qsavefile.h"
#include "core/Tools.h"
#include "format/KeePass2Reader.h"
#include "format/KeePass2Writer.h"
#include "keys/CompositeKey.h"
#include "keys/FileKey.h"
#include "keys/HmacSha1ChallengeResponseKey.h"
#include "keys/PasswordKey.h"

#include <QDebug>

int main(int argc, char **argv)
{

#ifdef QT_NO_DEBUG
    Tools::disableCoreDumps();
#endif

    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("kdbx-noyubikey-exporter");

    QCommandLineParser parser;
    parser.setApplicationDescription(QCoreApplication::translate("main", "Emergency tool to remove the Yubikey challenge-response protection from a KeepassX (*.kdbx) database.\n"
                                                                         "Use this tool to create a copy of the KeepassX (kdbx) database without the Yubikey challenge-response\n"
                                                                         "protection. The copy will be protected with the same password/keyfile than the source database.\n"
                                                                         "It will only work if you have a backuk of the HMAC key used to configure the Yubikey that protects the \n"
                                                                         "database.\n\n"
                                                                         "WARNING: Only use this tool on a trusted computer."));
    parser.addPositionalArgument("file", QCoreApplication::translate("main", "Filename of the password database to open (*.kdbx)."));

    QCommandLineOption keyfileOption(QStringList() << "k" << "keyfile",
                                     QCoreApplication::translate("main", "Key file of the database."),
                                     "keyfile");
    QCommandLineOption nopassOption(QStringList() << "n" << "nopass",
                                     QCoreApplication::translate("main", "Do not ask for password. To open a database that is not protected with a password."));
    QCommandLineOption hmacMode(QStringList() << "f" << "fixed",
                                     QCoreApplication::translate("main", "Use this option if the database is protected with a Yubikey configured with a "
                                                                         "fixed 64 bytes HMAC-SHA1 Mode."));

    parser.addHelpOption();
    parser.addOption(nopassOption);
    parser.addOption(keyfileOption);
    parser.addOption(hmacMode);

    parser.process(app);
    const QStringList args = parser.positionalArguments();

    bool noPass = parser.isSet(nopassOption);
    bool useKey = parser.isSet(keyfileOption);
    bool fixed64Mode = parser.isSet(hmacMode);

    QString keyfilePath = parser.value(keyfileOption);

    if(args.size() != 1) {
        fputs(qPrintable(parser.helpText()), stderr);
        return 1;
    }

    if(useKey && !QFile::exists(keyfilePath)) {
        qCritical("Unable to find key file '%s'.", qPrintable(keyfilePath));
        return 1;
    }

    if (!Crypto::init()) {
        qFatal("Fatal error while testing the cryptographic functions:\n%s", qPrintable(Crypto::errorString()));
        return 1;
    }

    QString databasePath = args.at(0);

    QFile dbFile(databasePath);
    if (!dbFile.exists()) {
        qCritical("Could not find database file '%s'.", qPrintable(databasePath));
        return 1;
    }
    if (!dbFile.open(QIODevice::ReadOnly)) {
        qCritical("Unable to open file '%s'.", qPrintable(dbFile.fileName()));
        return 1;
    }

    QString passwordStr;
    if (!noPass) {
        QTextStream inPass(stdin, QIODevice::ReadOnly);
        fputs(qPrintable("Enter the password (enter for empty string password): "), stdout);
        passwordStr = inPass.readLine();
    }

    QTextStream inHmacKey(stdin, QIODevice::ReadOnly);
    fputs(qPrintable("Enter the HMAC key used to configure the Yubikey (40 char hex): "), stdout);
    QByteArray hexhmackey = inHmacKey.readLine().toAscii();

    if (hexhmackey.size() != 40) {
        qWarning("Wrong HMAC key size, must be a 40 char hex value.");
        return 1;
    }

    QByteArray hmackey =  QByteArray::fromHex(hexhmackey);

    CompositeKey key;

    /* When adding subkeys to composite key keep the order: pass, keyfile, hmac */
    PasswordKey passKey;
    if (!noPass) {
        passKey.setPassword(passwordStr);
        key.addKey(passKey);
    }

    FileKey fileKey;
    if (useKey) {
        bool result = false;
        QString error_msg;

        result = fileKey.load(keyfilePath, &error_msg);
        if (result) {
            key.addKey(fileKey);
        }
        else {
            qWarning("Error opening key file: %s", qPrintable(error_msg));
            return 1;
        }

    }

    if (fixed64Mode) {
        HmacSha1ChallengeResponseKey challengeKey(hmackey, HmacSha1ChallengeResponseKey::FIXED64);
        key.addChallengeResponseKey(challengeKey);
    }
    else {
        HmacSha1ChallengeResponseKey challengeKey(hmackey, HmacSha1ChallengeResponseKey::VARIABLE);
        key.addChallengeResponseKey(challengeKey);
    }

    KeePass2Reader reader;
    Database* db = reader.readDatabase(&dbFile, key);

    if (reader.hasError()) {
        qCritical("Unable to open database file '%s'. %s", qPrintable(dbFile.fileName())
                  , qPrintable(reader.errorString()));
        return 1;
    }

    /* Setup new key with same password and/or key file used
     * to open the database but without the Yubikey challenge key.
    */
    CompositeKey newKey;

    if (!noPass) {
            newKey.addKey(passKey);
    }
    else if (noPass && !useKey) {
        QString newPassStr, newPassStrConf;

        QTextStream inPass(stdin, QIODevice::ReadOnly);
        fputs(qPrintable("The origin database is only protected with a Yubikey challenge-response code\n"
                         "you need to enter a password to protect the copy of the database.\n"
                         "Enter password: "), stdout);
        newPassStr = inPass.readLine();
        fputs(qPrintable("Repeat password: "), stdout);
        newPassStrConf = inPass.readLine();
        /* FIXME: do not allow or confirm to set password as empty string */
        if (newPassStr == newPassStrConf) {
            passKey.setPassword(newPassStr);
            newKey.addKey(passKey);
        }
        else {
            fputs(qPrintable("The passwords do not match.\n"), stdout);
            delete db;
            return 1;
        }
    }

    if (useKey) {
        fileKey.load(keyfilePath);
        newKey.addKey(fileKey);
    }

    /* Set the new key in the database replacing previous key */
    db->setKey(newKey);

    KeePass2Writer m_writer;

    QFileInfo fileInfo(dbFile);
    QString outFileName = fileInfo.canonicalPath() + "/" + fileInfo.baseName() +
                          "_noyubikey." + fileInfo.completeSuffix();

    if (!outFileName.isEmpty()) {
        bool result = false;

        QSaveFile saveFile(outFileName);
        if (saveFile.open(QIODevice::WriteOnly)) {
            m_writer.writeDatabase(&saveFile, db);
            result = saveFile.commit();
        }

        if (result) {
            fputs(qPrintable("A copy of the database without the Yubikey challenge-response key was saved to:\n"
                             + outFileName + "\n") , stdout);
        }
        else {
            qWarning("Writing the database failed with:\n%s\n", qPrintable(saveFile.errorString()));
            delete db;
            return 1;
        }
    }

    delete db;
    return 0;
}
