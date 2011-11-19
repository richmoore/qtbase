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

/*!
    \class QSslOcspVerifier
    \brief The QSslOcspVerifier class provides a simple API for checking
           the validity of an X509 certificate using OCSP.

    \ingroup network
    \ingroup ssl
    \inmodule QtNetwork


 */

#include "qsslsocket_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslcertificate_p.h"
#include "qsslcertificate.h"
#include "qdatetime.h"
#include "qnetworkaccessmanager.h"
#include "qnetworkrequest.h"
#include "qvarlengtharray.h"

#include <openssl/ocsp.h>

#include "qsslocspverifier.h"

QT_BEGIN_NAMESPACE

// Allowed clock skew in seconds
static int allowedClockSkew = 5;
// Max age allowed for precomputed responses (seconds), set to -1 to allow responses of
// any age (not 0 like the book says, the book is wrong!). Setting to 4 weeks for now.
static int maxResponseAge = 4*60*60*24*7;

class QSslOcspRequestPrivate
{
public:
    ~QSslOcspRequestPrivate()
    {
        if (request)
            q_OCSP_REQUEST_free(request);
    }

    OCSP_REQUEST *request;
    OCSP_CERTID *certId;
    QSslCertificate certToVerify;
    QAtomicInt ref;
};

class QSslOcspReplyPrivate
{
public:
    QSslOcspReplyPrivate()
        : response(0),
          basicresp(0),
          certStatus(QSslOcspReply::CertificateStatusUnknown),
          responseStatus(QSslOcspReply::ResponseInvalid),
          revokationReason(QSslOcspReply::RevokationNone)
    {

    }

    ~QSslOcspReplyPrivate() {
        if (response)
            q_OCSP_RESPONSE_free(response);
        if (basicresp)
            q_OCSP_BASICRESP_free(basicresp);
    }

    void decodeResponse(const QSslOcspRequest &request, const QList<QSslCertificate> &caCertificates);

    static QSslOcspReply::ResponseStatus opensslResponseStatusToResponseStatus(int status);
    static QSslOcspReply::CertificateStatus opensslCertificateStatusToCertificateStatus(int status);
    static QSslOcspReply::RevokationReason opensslRevokationReasonToRevokationReason(int reason);

public:
    OCSP_RESPONSE *response;
    OCSP_BASICRESP *basicresp;
    QSslOcspReply::CertificateStatus certStatus;
    QSslOcspReply::ResponseStatus responseStatus;
    QSslOcspReply::RevokationReason revokationReason;
    QAtomicInt ref;
};

//
// Request
//

QSslOcspRequest::QSslOcspRequest( const QSslCertificate &issuer, const QSslCertificate &toVerify )
    : d(new QSslOcspRequestPrivate)
{
    d->certToVerify = toVerify;

    d->request = q_OCSP_REQUEST_new();
    if ( !d->request )
        return;

    d->certId = q_OCSP_cert_to_id( 0, toVerify.d->x509, issuer.d->x509 );
    if (!d->certId || !q_OCSP_request_add0_id(d->request, d->certId)) {
        q_OCSP_REQUEST_free(d->request);
        d->request = 0;
        return;
    }
}

QSslOcspRequest::~QSslOcspRequest()
{
}

QSslOcspRequest::QSslOcspRequest(const QSslOcspRequest &other)
    : d(other.d)
{
}

QSslOcspRequest &QSslOcspRequest::operator=(const QSslOcspRequest &other)
{
    d = other.d;
    return *this;
}

bool QSslOcspRequest::isValid() const
{
    return (d->request != 0);
}

QByteArray QSslOcspRequest::toByteArray() const
{
    QByteArray result;
    if (!isValid())
        return result;

    BIO *requestBio = q_BIO_new(q_BIO_s_mem());
    if (!requestBio)
        return result;

    // Write to the BIO
    q_i2d_OCSP_REQUEST_bio(requestBio, d->request);

    QVarLengthArray<char, 4096> data;
    int count = q_BIO_read(requestBio, data.data(), 4096);
    if ( count > 0 ) {
        result = QByteArray( data.data(), count );
    }

    q_BIO_free(requestBio);

    return result;
}

QNetworkReply *QSslOcspRequest::send(QNetworkAccessManager *manager)
{
    if (!isValid())
        return 0;

    //### Port to new extension support
    //QStringList ocspUris = d->certToVerify.ocspUris();
    //if (ocspUris.isEmpty())
    //    return 0;

    //QNetworkRequest req(ocspUris[0]);
    QNetworkRequest req( QString("http://ocsp.entrust.net/") );//used to force an unknown response
    req.setHeader(QNetworkRequest::ContentTypeHeader, QLatin1String("application/ocsp-request"));
    QNetworkReply *reply = manager->post(req, toByteArray());

    return reply;
}

//
// Reply
//

QSslOcspReply::QSslOcspReply(const QSslOcspRequest &request, const QByteArray &replyArray, const QList<QSslCertificate> &caCertificates)
    : d(new QSslOcspReplyPrivate)
{
    d->response = 0;
#if 1
    BIO *replyBio = q_BIO_new(q_BIO_s_mem());
    if (!replyBio)
        return;

    // Copy the data into the bio
    q_BIO_write(replyBio, replyArray.constData(), replyArray.size());
#else
    BIO *replyBio = q_BIO_new_file("gmail-response.out", "rb");
    if (!replyBio)
        return;
#endif
    d->response = q_d2i_OCSP_RESPONSE_bio(replyBio, 0);
    q_BIO_free(replyBio);

    d->decodeResponse(request, caCertificates);
}

QSslOcspReply::QSslOcspReply(const QSslOcspReply &other)
    : d(other.d)
{
}

QSslOcspReply::~QSslOcspReply()
{
}

void QSslOcspReplyPrivate::decodeResponse(const QSslOcspRequest &request, const QList<QSslCertificate> &caCertificates)
{
    Q_ASSERT(response);

    responseStatus = opensslResponseStatusToResponseStatus(q_OCSP_response_status(response));
    qDebug() << "OCSP Status: " << responseStatus;
    if (responseStatus != QSslOcspReply::ResponseSuccessful) {
        return;
    }

    // Get the basic response
    basicresp = q_OCSP_response_get1_basic(response);
    if (!basicresp) {
        // We have a valid response that doesn't contain a basic response. Something is
        // very screwed up.
        responseStatus = QSslOcspReply::ResponseUnknownError;
        return;
    }

    //
    // Check the request is correctly certifed
    //

    // Create the certificate store
    X509_STORE *certStore = q_X509_STORE_new();
    if (!certStore) {
        qWarning() << "Unable to create certificate store";
        responseStatus = QSslOcspReply::ResponseUnknownError;
        return;
    }

    foreach (const QSslCertificate &caCertificate, caCertificates)
        q_X509_STORE_add_cert(certStore, (X509 *)caCertificate.handle());

    qDebug() << "Store created";
    int verifyResult = q_OCSP_basic_verify(basicresp, 0, certStore, 0);
    qDebug() << "verification result" << verifyResult;
    if (verifyResult < 0) {
        qDebug() << "OCSP response verification failed";
        
    }
    qDebug() << "OCSP response verification good";

    q_X509_STORE_free(certStore);
    
    //
    // Get the status
    //
    int status;
    int reason=-1; // This is only populated sometimes, so lets avoid reading crap later
    ASN1_GENERALIZEDTIME *producedAt;
    ASN1_GENERALIZEDTIME *thisUpdate;
    ASN1_GENERALIZEDTIME *nextUpdate;

    if (!q_OCSP_resp_find_status(basicresp, request.d->certId, &status, &reason, &producedAt, &thisUpdate, &nextUpdate)) {
        responseStatus = QSslOcspReply::ResponseInvalid;
        return;
    }

    qDebug() << "Status: " << status << " Reason: " << reason;

    certStatus = opensslCertificateStatusToCertificateStatus(status);
    if (certStatus == QSslOcspReply::CertificateStatusRevoked) {
        revokationReason = opensslRevokationReasonToRevokationReason(reason);
    }

    // Check if the response is one we can accept (not too old etc.)
    int validityResult = q_OCSP_check_validity(thisUpdate, nextUpdate, allowedClockSkew, maxResponseAge);
    if (!validityResult) {
        qDebug() << "Validity check failed" << validityResult;
        responseStatus = QSslOcspReply::ResponseInvalid;
        return;
    }
}

QSslOcspReply::ResponseStatus QSslOcspReplyPrivate::opensslResponseStatusToResponseStatus(int status)
{
    QSslOcspReply::ResponseStatus result;
    switch(status) {
    case OCSP_RESPONSE_STATUS_SUCCESSFUL:
        result = QSslOcspReply::ResponseSuccessful;
        break;
    case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
        result = QSslOcspReply::ResponseMalformedRequest;
        break;
    case OCSP_RESPONSE_STATUS_INTERNALERROR:
        result = QSslOcspReply::ResponseInternalError;
        break;
    case OCSP_RESPONSE_STATUS_TRYLATER:
        result = QSslOcspReply::ResponseTryLater;
        break;
    case OCSP_RESPONSE_STATUS_SIGREQUIRED:
        result = QSslOcspReply::ResponseSigRequired;
        break;
    case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
        result = QSslOcspReply::ResponseUnauthorized;
        break;
    default:
        result = QSslOcspReply::ResponseUnknownError;
    }

    return result;
}

QSslOcspReply::CertificateStatus QSslOcspReplyPrivate::opensslCertificateStatusToCertificateStatus(int status)
{
    QSslOcspReply::CertificateStatus result;
    switch(status) {
    case V_OCSP_CERTSTATUS_GOOD:
        result = QSslOcspReply::CertificateStatusGood;
        break;
    case V_OCSP_CERTSTATUS_REVOKED:
        result = QSslOcspReply::CertificateStatusRevoked;
        break;
    case V_OCSP_CERTSTATUS_UNKNOWN:
        // FALL THRU
    default:
        result = QSslOcspReply::CertificateStatusUnknown;
    }

    return result;
}

QSslOcspReply::RevokationReason QSslOcspReplyPrivate::opensslRevokationReasonToRevokationReason(int reason)
{
    QSslOcspReply::RevokationReason result;

    switch(reason) {
    case OCSP_REVOKED_STATUS_NOSTATUS:
        result = QSslOcspReply::RevokationNone;
        break;
    case OCSP_REVOKED_STATUS_UNSPECIFIED:
        result = QSslOcspReply::RevokationUnspecified;
        break;
    case OCSP_REVOKED_STATUS_KEYCOMPROMISE:
        result = QSslOcspReply::RevokationKeyCompromise;
        break;
    case OCSP_REVOKED_STATUS_CACOMPROMISE:
        result = QSslOcspReply::RevokationCACompromise;
        break;
    case OCSP_REVOKED_STATUS_AFFILIATIONCHANGED:
        result = QSslOcspReply::RevokationAffiliationChanged;
        break;
    case OCSP_REVOKED_STATUS_SUPERSEDED:
        result = QSslOcspReply::RevokationSuperseded;
        break;
    case OCSP_REVOKED_STATUS_CESSATIONOFOPERATION:
        result = QSslOcspReply::RevokationCessationOfOperation;
        break;
    case OCSP_REVOKED_STATUS_CERTIFICATEHOLD:
        result = QSslOcspReply::RevokationCertificateHold;
        break;
    case OCSP_REVOKED_STATUS_REMOVEFROMCRL:
        result = QSslOcspReply::RevokationRemoveFromCRL;
        break;
    default:
        qWarning() << "Unkown revokation reason specified" << reason;
    }
    
    return result;
}

QSslOcspReply &QSslOcspReply::operator=(const QSslOcspReply &other)
{
    d = other.d;
    return *this;
}

bool QSslOcspReply::isValid() const
{
    return (d->response != 0) && (d->responseStatus==ResponseSuccessful);
}

QSslOcspReply::ResponseStatus QSslOcspReply::responseStatus() const
{
    return d->responseStatus;
}

QSslOcspReply::CertificateStatus QSslOcspReply::certificateStatus() const
{
    return d->certStatus;
}

QSslOcspReply::RevokationReason QSslOcspReply::revokationReason() const
{
    return d->revokationReason;
}

//
// Verifier
//

QSslOcspVerifier::QSslOcspVerifier(QObject *parent)
    : QObject(parent)
{
    QSslSocketPrivate::ensureInitialized();
}

QSslOcspVerifier::~QSslOcspVerifier()
{
}

QSslOcspRequest QSslOcspVerifier::createRequest(const QSslCertificate &issuer, const QSslCertificate &toVerify)
{
    QSslOcspRequest req(issuer, toVerify);
    return req;
}

QSslOcspReply QSslOcspVerifier::createReply(const QSslOcspRequest &request, const QByteArray &replyArray)
{
    QSslOcspReply reply(request, replyArray, QSslSocket::defaultCaCertificates());
    return reply;
}

QSslOcspReply QSslOcspVerifier::createReply(const QSslOcspRequest &request,
                                            const QByteArray &replyArray,
                                            const QList<QSslCertificate> &caCertificates)
{
    QSslOcspReply reply(request, replyArray, caCertificates);
    return reply;
}

QT_END_NAMESPACE
