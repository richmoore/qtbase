#include <QtTest/QtTest>
#include <qdebug.h>
#include <qnetworkaccessmanager.h>
#include <qnetworkreply.h>
#include <qsslocspverifier.h>
#include <qsslcertificate.h>

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


class tst_QSslOcspVerifier : public QObject
{
    Q_OBJECT

    QString oldCurrentDir;

public:
    tst_QSslOcspVerifier();
    virtual ~tst_QSslOcspVerifier();

public slots:

    void initTestCase_data();
    void init();
    void cleanup();

private slots:
    void createRequest();
    void sendRequest();
};

tst_QSslOcspVerifier::tst_QSslOcspVerifier()
{
}

tst_QSslOcspVerifier::~tst_QSslOcspVerifier()
{
}

void tst_QSslOcspVerifier::initTestCase_data()
{
}

void tst_QSslOcspVerifier::init()
{
    QString srcdir(QLatin1String(SRCDIR));
    if (!srcdir.isEmpty()) {
        oldCurrentDir = QDir::current().absolutePath();
        QDir::setCurrent(srcdir);
    }
}

void tst_QSslOcspVerifier::cleanup()
{
    if (!oldCurrentDir.isEmpty()) {
        QDir::setCurrent(oldCurrentDir);
    }

}

void tst_QSslOcspVerifier::createRequest()
{
    QSslOcspVerifier verifier;

    QSslCertificate issuer = QSslCertificate::fromPath(SRCDIR "certificates/ca-cert.pem").first();
    QSslCertificate cert = QSslCertificate::fromPath(SRCDIR "certificates/cert.pem").first();

    QSslOcspRequest request = verifier.createRequest(issuer, cert);
    QByteArray reqArray = request.toByteArray();
    QFile out( "request.out" );
    if (!out.open(QIODevice::WriteOnly)) {
        // error
        qDebug() << "Unable to open  file";
        return;
    }

    out.write(reqArray);
    out.close();
}

void tst_QSslOcspVerifier::sendRequest()
{
    QSslOcspVerifier verifier;

    // Build request
    QSslCertificate issuer = QSslCertificate::fromPath(SRCDIR "certificates/gmail-issuer.pem").first();
    QSslCertificate cert = QSslCertificate::fromPath(SRCDIR "certificates/gmail.pem").first();

    QSslOcspRequest request = verifier.createRequest(issuer, cert);

    QFile reqout( "gmail-request.out" );
    if (!reqout.open(QIODevice::WriteOnly)) {
        // error
        qDebug() << "Unable to open  file";
        return;
    }

    reqout.write(request.toByteArray());
    reqout.close();

    // Send request
    QNetworkAccessManager manager;
    QNetworkReply *networkReply = request.send(&manager);
    qDebug() << "request in flight";
    waitForSignal(networkReply, SIGNAL(finished()));

    // Handle reply
    QVERIFY(networkReply->error() == QNetworkReply::NoError);

    QByteArray responseArray = networkReply->readAll();
    QFile out( "gmail-response.out" );
    if (!out.open(QIODevice::WriteOnly)) {
        // error
        qDebug() << "Unable to open  file";
        return;
    }

    out.write(responseArray);
    out.close();

    QSslOcspReply reply = verifier.createReply(request, responseArray);
    qDebug() << "isValid" << reply.isValid();
    qDebug() << "responseStatus" << reply.responseStatus();
    qDebug() << "certificateStatus" << reply.certificateStatus();
    qDebug() << "revokationReason" << reply.revokationReason();
}

QTEST_MAIN(tst_QSslOcspVerifier)
#include "tst_qsslocspverifier.moc"
