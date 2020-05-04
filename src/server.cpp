#include "server.h"
#include "client.h"
#include "database.h"
#include "thread.h"

#include <QtDebug>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QTcpServer>

#include <cryptopp/filters.h>
#include <cryptopp/sha3.h>
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::HashFilter;
using CryptoPP::SHA3_512;

#include <oqs/oqs.h>

QMultiHash<QByteArray, Client *> Server::connected;
QMultiHash<QByteArray, Client *> Server::participants;
QByteArray Server::id;
QVector<quint8> Server::public_key;
QVector<quint8> Server::secret_key;
QSettings Server::settings
{
    "server.ini",
    QSettings::IniFormat
};

Server::Server()
{
    if (!QDir().mkpath("usershare"))
    {
        error("Unable to create usershare folder");
    }

    initCrypto();
    initDatabase();

    if (!settings.contains("Name"))
    {
        error("Server name not specified");
    }

    if (!settings.contains("Port"))
    {
        error("Listening port not specified");
    }

    auto port = settings.value("Port").toInt();

    auto server = new QTcpServer;

    Thread::prepare();

    QObject::connect(server, &QTcpServer::newConnection, [ = ]
    {
        auto thread = Thread::get();

        auto client = new Client;
        auto socket = server->nextPendingConnection();

        socket->setParent(nullptr);

        client->moveToThread(thread);
        socket->moveToThread(thread);

        Thread::attach(client);

        QMetaObject::invokeMethod(client, "run",
                                  Q_ARG(QTcpSocket *, socket));
    });

    if (!server->listen(QHostAddress::Any, port))
    {
        error(server->errorString());
    }

    qInfo() << "Server started listening and is waiting for new connections";
}

const QVector<quint8> &Server::getPublicKey()
{
    return public_key;
}

const QVector<quint8> &Server::getSecretKey()
{
    return secret_key;
}

QSettings &Server::getSettings()
{
    return settings;
}

void Server::error(const QString &reason)
{
    qCritical().noquote() << reason;
    exit(EXIT_FAILURE);
}

void Server::initCrypto()
{
    #if !defined (OQS_ENABLE_KEM_sidh_p751) || !defined (OQS_ENABLE_SIG_picnic2_L5_FS)
    error("The required post quantum algorithms are not available for use");
    #endif

    public_key.resize(OQS_SIG_picnic2_L5_FS_length_public_key);
    secret_key.resize(OQS_SIG_picnic2_L5_FS_length_secret_key);

    QFile crt("server.crt");

    if (crt.exists())
    {
        if (!crt.open(QIODevice::ReadOnly))
        {
            error("Unable to open certificate file");
        }

        crt.read(reinterpret_cast<char *>(public_key.data()), public_key.size());
        crt.read(reinterpret_cast<char *>(secret_key.data()), secret_key.size());
    }
    else
    {
        if (!crt.open(QIODevice::NewOnly))
        {
            error("Unable to create certificate file");
        }

        auto rc = OQS_SIG_picnic2_L5_FS_keypair(public_key.data(),
                                                secret_key.data());

        if (rc != OQS_SUCCESS)
        {
            error("Failed to generate signature key pair");
        }

        crt.write(reinterpret_cast<const char *>(public_key.constData()), public_key.size());
        crt.write(reinterpret_cast<const char *>(secret_key.constData()), secret_key.size());
    }

    crt.close();

    SHA3_512 hash;
    id.resize(hash.DigestSize());

    ArraySource(public_key.constData(),
                public_key.size(), true,
                new HashFilter(
                    hash,
                    new ArraySink(reinterpret_cast<quint8 *>(id.data()), id.size())
                ));

    qInfo().noquote() << "Server id:" << id.toHex();
}

void Server::initDatabase()
{
    if (!QSqlDatabase::isDriverAvailable("QPSQL"))
    {
        error("Database driver not found");
    }

    if (!settings.contains("DbName")
            || !settings.contains("DbHost")
            || !settings.contains("DbPort")
            || !settings.contains("DbUser")
            || !settings.contains("DbPass"))
    {
        error("Database credentials not specified");
    }

    auto name = settings.value("DbName").toString();
    auto host = settings.value("DbHost").toString();
    auto port = settings.value("DbPort").toInt();
    auto user = settings.value("DbUser").toString();
    auto pass = settings.value("DbPass").toString();

    auto db = QSqlDatabase::addDatabase("QPSQL");
    db.setDatabaseName(name);
    db.setHostName(host);
    db.setPort(port);
    db.setUserName(user);
    db.setPassword(pass);

    if (!db.open())
    {
        error("Could not open database");
    }

    QSqlQuery query;

    if (!query.exec("CREATE TABLE IF NOT EXISTS ARCHIVE"
                    "("
                    "ID         SERIAL PRIMARY KEY,"
                    "TIMESTAMP  BIGINT NOT NULL,"
                    "ID_MESSAGE BYTEA  NOT NULL UNIQUE,"
                    "ID_ROOM    BYTEA  NOT NULL,"
                    "ID_SENDER  TEXT   NOT NULL,"
                    "CONTENT    TEXT   NOT NULL"
                    ")")
            || !query.exec("CREATE TABLE IF NOT EXISTS ROOMS"
                           "("
                           "ID   BYTEA NOT NULL UNIQUE,"
                           "NAME TEXT  NOT NULL UNIQUE"
                           ")")
            || !query.exec("CREATE TABLE IF NOT EXISTS USERS"
                           "("
                           "USERNAME TEXT  NOT NULL UNIQUE,"
                           "DERIVED  BYTEA NOT NULL UNIQUE,"
                           "SALT     BYTEA NOT NULL UNIQUE"
                           ")"))
    {
        error(query.lastError().text());
    }
}
