/****************************************************************************
**
** Copyright (C) 2011 Richard J. Moore, rich@kde.org.
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the test suite of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** GNU Lesser General Public License Usage
** This file may be used under the terms of the GNU Lesser General Public
** License version 2.1 as published by the Free Software Foundation and
** appearing in the file LICENSE.LGPL included in the packaging of this
** file. Please review the following information to ensure the GNU Lesser
** General Public License version 2.1 requirements will be met:
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Nokia gives you certain additional
** rights. These rights are described in the Nokia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU General
** Public License version 3.0 as published by the Free Software Foundation
** and appearing in the file LICENSE.GPL included in the packaging of this
** file. Please review the following information to ensure the GNU General
** Public License version 3.0 requirements will be met:
** http://www.gnu.org/copyleft/gpl.html.
**
** Other Usage
** Alternatively, this file may be used in accordance with the terms and
** conditions contained in a signed written agreement between you and Nokia.
**
**
**
**
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include <QtCore/QCoreApplication>
#include <QtCore/QTextStream>
#include <QtCore/QDebug>
#include <QtCore/QStringList>
#include <QtNetwork/qsslocspverifier.h>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtTest/QtTest>

#include <stdio.h>


/**
 * Starts an event loop that runs until the given signal is received.
 * Optionally the event loop
 * can return earlier on a timeout.
 *
 * \return \p true if the requested signal was received
 *         \p false on timeout
 */
static bool waitForSignal(QObject* obj, const char* signal, int timeout = 10000)
{
    QEventLoop loop;
    QObject::connect(obj, signal, &loop, SLOT(quit()));
    QTimer timer;
    QSignalSpy timeoutSpy(&timer, SIGNAL(timeout()));
    if (timeout > 0) {
        QObject::connect(&timer, SIGNAL(timeout()), &loop, SLOT(quit()));
        timer.setSingleShot(true);
        timer.start(timeout);
    }
    loop.exec();
    return timeoutSpy.isEmpty();
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    if (argc < 3) {
        QTextStream out(stdout);
        out << "Usage: " << argv[0] << " host port" << endl;
        return 1;
    }

    QString host = QString::fromLocal8Bit(argv[1]);
    int port = QString::fromLocal8Bit(argv[2]).toInt();

    QSslSocket socket;
    socket.connectToHostEncrypted(host, port);

    if ( !socket.waitForEncrypted() ) {
        qDebug() << socket.errorString();
        return 1;
    }

    qDebug() << "Connected to server";

    QList<QSslCertificate> certChain = socket.peerCertificateChain();

    qDebug() << "Chain length" << certChain.length();
    qDebug() << "Subject:" << certChain[0].subjectInfo(QSslCertificate::CommonName);
    qDebug() << "Issuer:" << certChain[0].issuerInfo(QSslCertificate::Organization);

    QSslOcspRequest ocspReq(certChain[1], certChain[0]);
    if (ocspReq.isNull()) {
        qDebug() << "OCSP request is null";
        return 1;
    }

    // Send request
    QNetworkAccessManager manager;
    QNetworkReply *networkReply = ocspReq.send(&manager);
    qDebug() << "request in flight";
    waitForSignal(networkReply, SIGNAL(finished()));

    if (networkReply->error() != QNetworkReply::NoError) {
        qDebug() << "Network error";
        return 1;
    }

    // Read response
    QByteArray response = networkReply->readAll();

    // Check response
    QSslOcspReply ocspResp(ocspReq, response);
    if (ocspResp.isNull()) {
        qDebug() << "OCSP reply is null";
        return 1;
    }

    // Check signature
    QList<QSslCertificate> caCerts = QSslSocket::defaultCaCertificates();
    certChain.removeFirst();

    if (!ocspResp.hasValidSignature(certChain[0])) {
        qDebug() << "Signature: Invalid";
    } else {
        qDebug() << "Signature: Valid";
    }

    switch (ocspResp.responseStatus()) {
    case QSslOcspReply::ResponseInvalid:
        qDebug() << "Response Status: Invalid";
        break;
    case QSslOcspReply::ResponseSuccessful:
        qDebug() << "Response Status: Success";
        break;
    default:
        qDebug() << "Response Status: " << ocspResp.responseStatus();
        break;
    }

    switch(ocspResp.certificateStatus()) {
    case QSslOcspReply::CertificateStatusGood:
        qDebug() << "Certificate Status: Good";
        break;
    case QSslOcspReply::CertificateStatusRevoked:
        qDebug() << "Certificate Status: Revoked";
        qDebug() << "Revokation Reason:" << ocspResp.revokationReason();
        break;
    case QSslOcspReply::CertificateStatusUnknown:
        qDebug() << "Certificate Status: Unknown";
        break;
    }

    return 0;
}
