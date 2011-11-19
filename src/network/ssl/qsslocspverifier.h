/****************************************************************************
**
** Copyright (C) 2011 Richard J. Moore <rich@kde.org>
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the QtNetwork module of the Qt Toolkit.
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

#ifndef QSSLOCSPVERIFIER_H
#define QSSLOCSPVERIFIER_H

#include <QtCore/qnamespace.h>
#include <QtCore/qsharedpointer.h>

QT_BEGIN_HEADER

QT_BEGIN_NAMESPACE

QT_MODULE(Network)

#ifndef QT_NO_OPENSSL

class QSslCertificate;
class QNetworkAccessManager;
class QNetworkReply;

class QSslOcspRequestPrivate;
class QSslOcspReplyPrivate;

class Q_NETWORK_EXPORT QSslOcspRequest
{
public:
    QSslOcspRequest(const QSslCertificate &issuer, const QSslCertificate &toVerify);
    QSslOcspRequest(const QSslOcspRequest &other);
    ~QSslOcspRequest();

    QSslOcspRequest &operator=(const QSslOcspRequest &other);

    bool isValid() const;

    QByteArray toByteArray() const;

    QNetworkReply *send(QNetworkAccessManager *manager);

private:
    QExplicitlySharedDataPointer<QSslOcspRequestPrivate> d;

    friend class QSslOcspRequestPrivate;
    friend class QSslOcspReplyPrivate;   
    friend class QSslOcspVerifier;
};

class Q_NETWORK_EXPORT QSslOcspReply
{
public:
    enum CertificateStatus {
        CertificateStatusGood,
        CertificateStatusRevoked,
        CertificateStatusUnknown
    };

    enum ResponseStatus {
        ResponseInvalid=-2,
        ResponseUnknownError=-1,
        ResponseSuccessful=0,
        ResponseMalformedRequest,
        ResponseInternalError,
        ResponseTryLater,
        ResponseSigRequired,
        ResponseUnauthorized
    };

    enum RevokationReason {
        RevokationNone=-1,
        RevokationUnspecified,
        RevokationKeyCompromise,
        RevokationCACompromise,
        RevokationAffiliationChanged,
        RevokationSuperseded,
        RevokationCessationOfOperation,
        RevokationCertificateHold,
        RevokationRemoveFromCRL
    };

    QSslOcspReply(const QSslOcspRequest &request, const QByteArray &reply, const QList<QSslCertificate> &caCertificates);
    QSslOcspReply(const QSslOcspReply &other);
    ~QSslOcspReply();

    QSslOcspReply &operator=(const QSslOcspReply &other);

    bool isValid() const;

    ResponseStatus responseStatus() const;
    CertificateStatus certificateStatus() const;
    RevokationReason revokationReason() const;

private:
    QExplicitlySharedDataPointer<QSslOcspReplyPrivate> d;

    friend class QSslOcspReplyPrivate;
    friend class QSslOcspVerifier;
};

class Q_NETWORK_EXPORT QSslOcspVerifier : public QObject
{
    Q_OBJECT
public:
    QSslOcspVerifier(QObject *parent = 0);
    ~QSslOcspVerifier();

    QSslOcspRequest createRequest(const QSslCertificate &issuer, const QSslCertificate &toVerify);
    QSslOcspReply createReply(const QSslOcspRequest &request, const QByteArray &reply);
    QSslOcspReply createReply(const QSslOcspRequest &request, const QByteArray &reply, const QList<QSslCertificate> &caCertificates);
};

#endif // QT_NO_OPENSSL

QT_END_NAMESPACE

#endif // QSSLOCSPVERIFIER_H
