#include "client.h"
#include "database.h"
#include "file.h"
#include "server.h"

#include <QDateTime>
#include <QDir>
#include <QHostAddress>
#include <QSqlError>
#include <QSqlQuery>

#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
using CryptoPP::PKCS5_PBKDF2_HMAC;
using CryptoPP::SHA3_512;

#ifdef __cplusplus
extern "C" {
#include <oqs/oqs.h>
}
#endif

Client::Client()
    : interruptionRequested(false)
    , reading(false)
    , writing(false)
    , encryption(false)
    , public_key(OQS_KEM_sike_p751_length_public_key)
    , secret_key(OQS_KEM_sike_p751_length_secret_key)
    , shared_secret(OQS_KEM_sike_p751_length_shared_secret)
{
}

Client::~Client()
{
    socket->disconnect();
    socket->deleteLater();

    if (!id_room.isEmpty())
    {
        leaveRoom();
    }

    Server::connected.remove(id, this);
}

void Client::run(QTcpSocket *socket)
{
    this->socket = socket;
    stream.setDevice(socket);

    connect(socket, &QTcpSocket::disconnected,
            this, &Client::onDisconnected);
    connect(socket, &QTcpSocket::readyRead,
            this, &Client::onReadyRead);

    disconnectTimer = new QTimer(this);
    disconnectTimer->callOnTimeout([ = ]
    {
        close("Connection timed out");
    });
    disconnectTimer->setInterval(5000);

    pingTimer = new QTimer(this);
    pingTimer->callOnTimeout([ = ]
    {
        pingTimestamp = QDateTime::currentSecsSinceEpoch();

        sendOne(PacketType::Ping, QVariant::fromValue(
        Ping {
            pingTimestamp
        }));

        disconnectTimer->start();
    });
    pingTimer->setInterval(30000);

    OQS_STATUS rc;

    rc = OQS_KEM_sike_p751_keypair(public_key.data(),
                                   secret_key.data());

    if (rc != OQS_SUCCESS)
    {
        close("Failed to generate ephemeral key pair");
        return;
    }

    QVector<quint8> signature(OQS_SIG_picnic2_L5_FS_length_signature);
    size_t signature_len;

    rc = OQS_SIG_picnic2_L5_FS_sign(signature.data(),
                                    &signature_len,
                                    public_key.constData(),
                                    public_key.size(),
                                    Server::getSecretKey().constData());

    if (rc != OQS_SUCCESS)
    {
        close("Failed to sign ephemeral public key");
        return;
    }

    signature.resize(signature_len);

    sendOne(PacketType::Handshake, QVariant::fromValue(
                ServerKeyExchange
    {
        {
            Server::getPublicKey(),
            public_key
        },
        signature
    }));

    pingTimer->start();
}

void Client::close(QString reason)
{
    if (!reason.isEmpty())
    {
        qCritical().noquote() << QString("[%1]: %2")
                              .arg(id.isEmpty()
                                   ? QString("%1:%2")
                                   .arg(socket->peerAddress().toString())
                                   .arg(socket->peerPort())
                                   : id.toHex())
                              .arg(reason);
    }

    socket->close();
}

void Client::onDisconnected()
{
    interruptionRequested = true;

    if (reading)
    {
        connect(this, &Client::read,
                this, &Client::deleteLater);
    }
    else if (writing)
    {
        connect(this, &Client::written,
                this, &Client::deleteLater);
    }
    else
    {
        deleteLater();
    }
}

void Client::onReadyRead()
{
    if (interruptionRequested)
    {
        return;
    }

    reading = true;

    while (!socket->atEnd())
    {
        stream.startTransaction();

        quint8 type;
        quint16 length;
        stream >> type >> length;

        QByteArray in;
        QVector<quint8> crypto[2];

        if (length > 0)
        {
            in.resize(length);

            if (encryption)
            {
                crypto[0].resize(dec.DigestSize());
                crypto[1].resize(dec.DefaultIVLength());

                stream.readRawData(reinterpret_cast<char *>(crypto[0].data()), crypto[0].size());
                stream.readRawData(reinterpret_cast<char *>(crypto[1].data()), crypto[1].size());
            }

            stream.readRawData(in.data(), in.size());
        }

        if (!stream.commitTransaction())
        {
            break;
        }

        QVariant v;

        if (length > 0)
        {
            if (encryption)
            {
                dec.SetKeyWithIV(shared_secret.constData(),
                                 shared_secret.size(),
                                 crypto[1].constData(),
                                 crypto[1].size());

                if (!dec.DecryptAndVerify(reinterpret_cast<quint8 *>(in.data()),
                                          crypto[0].constData(),
                                          crypto[0].size(),
                                          crypto[1].constData(),
                                          crypto[1].size(),
                                          nullptr,
                                          0,
                                          reinterpret_cast<const quint8 *>(in.constData()), in.size()))
                {
                    close("Failed to decrypt incoming packet");
                    break;
                }
            }

            QDataStream ds(&in, QIODevice::ReadOnly);
            v.load(ds);
        }

        bool ok = true;

        if (!encryption)
        {
            switch (type)
            {
            case quint8(PacketType::Handshake):
            {
                if ((ok = v.canConvert<ClientKeyExchange>()))
                {
                    doHandshake(v.value<ClientKeyExchange>());
                }
            }
            break;
            }
        }
        else
        {
            switch (type)
            {
            case quint8(PacketType::RtAuthorization):
            {
                if ((ok = v.canConvert<RtAuthorization>()))
                {
                    doRtAuthorization(v.value<RtAuthorization>());
                }
            }
            break;

            case quint8(PacketType::Synchronize):
            {
                if ((ok = v.canConvert<Synchronize>()))
                {
                    doSynchronize(v.value<Synchronize>());
                }
            }
            break;

            case quint8(PacketType::Message):
            {
                if ((ok = v.canConvert<Message>()))
                {
                    doMessage(v.value<Message>());
                }
            }
            break;

            case quint8(PacketType::RtRoom):
            {
                if ((ok = v.canConvert<RtRoom>()))
                {
                    doRtRoom(v.value<RtRoom>());
                }
            }
            break;

            case quint8(PacketType::RtUpload):
            {
                if ((ok = v.canConvert<RtUpload>()))
                {
                    doRtUpload(v.value<RtUpload>());
                }
            }
            break;

            case quint8(PacketType::Upload):
            {
                if ((ok = v.canConvert<Upload>()))
                {
                    doUpload(v.value<Upload>());
                }
            }
            break;

            case quint8(PacketType::UploadState):
            {
                if ((ok = v.canConvert<UploadState>()))
                {
                    doUploadState(v.value<UploadState>());
                }
            }
            break;

            case quint8(PacketType::Pong):
            {
                if ((ok = v.canConvert<Ping>()))
                {
                    doPong(v.value<Ping>());
                }
            }
            break;
            }
        }

        if (!ok)
        {
            close("Failed to deserialize incoming packet");
            break;
        }
    }

    reading = false;
    emit read();
}

void Client::doHandshake(ClientKeyExchange d)
{
    auto rc = OQS_KEM_sike_p751_decaps(shared_secret.data(),
                                       d.ciphertext.constData(),
                                       secret_key.constData());

    if (rc != OQS_SUCCESS)
    {
        close(tr("Failed to reach shared secret"));
        return;
    }

    encryption = true;

    public_key.clear();
    secret_key.clear();
}

void DeriveKey(QByteArray &derived, const QByteArray &password, const QByteArray &salt)
{
    PKCS5_PBKDF2_HMAC<SHA3_512> pbkdf;
    pbkdf.DeriveKey(reinterpret_cast<quint8 *>(derived.data()), derived.size(),
                    0,
                    reinterpret_cast<const quint8 *>(password.constData()), password.size(),
                    reinterpret_cast<const quint8 *>(salt.constData()), salt.size(),
                    100000);
}

void Client::doRtAuthorization(RtAuthorization d)
{
    QSqlQuery query(Database::get());
    query.prepare("SELECT DERIVED, SALT FROM USERS"
                  " WHERE USERNAME = ?");
    query.addBindValue(d.username);

    if (!query.exec())
    {
        Server::error(query.lastError().text());
    }

    if (query.next())
    {
        switch (d.request)
        {
        case RtAuthorization::Signin:
        {
            QByteArray derived;
            derived.resize(64);

            DeriveKey(derived, d.password, query.value(1).toByteArray());

            if (derived != query.value(0).toByteArray())
            {
                sendOne(PacketType::ReAuthorization, QVariant::fromValue(
                            ReAuthorization
                {
                    ReAuthorization::ErrorOccurred,
                    ReAuthorization::InvalidPassword
                }));
                return;
            }
        }
        break;

        case RtAuthorization::Signup:
        {
            sendOne(PacketType::ReAuthorization, QVariant::fromValue(
                        ReAuthorization
            {
                ReAuthorization::ErrorOccurred,
                ReAuthorization::UserExists
            }));
        }

        return;
        }
    }
    else
    {
        switch (d.request)
        {
        case RtAuthorization::Signin:
        {
            sendOne(PacketType::ReAuthorization, QVariant::fromValue(
                        ReAuthorization
            {
                ReAuthorization::ErrorOccurred,
                ReAuthorization::InvalidUsername
            }));
        }

        return;

        case RtAuthorization::Signup:
        {
            QByteArray derived;
            QByteArray salt;
            derived.resize(64);
            salt.resize(16);

            rng.GenerateBlock(reinterpret_cast<quint8 *>(salt.data()), salt.size());

            DeriveKey(derived, d.password, salt);

            query.prepare("INSERT INTO USERS (USERNAME, DERIVED, SALT)"
                          " VALUES (?, ?, ?)");
            query.addBindValue(d.username);
            query.addBindValue(derived);
            query.addBindValue(salt);

            if (!query.exec())
            {
                Server::error(query.lastError().text());
            }
        }
        break;
        }
    }

    id = d.username;
    Server::connected.insertMulti(id, this);

    sendOne(PacketType::ReAuthorization, QVariant::fromValue(
                ReAuthorization
    {
        ReAuthorization::Authorized,
        ReAuthorization::NoError
    }));

    QVector<Room> rooms;

    if (!query.exec("SELECT *"
                    " FROM ROOMS"))
    {
        Server::error(query.lastError().text());
    }

    while (query.next())
    {
        rooms.append(Room
        {
            query.value(0).toByteArray(),
            query.value(1).toString()
        });
    }

    sendOne(PacketType::Established, QVariant::fromValue(
                Established
    {
        Server::getSettings().value("Name").toString(),
        Server::getSettings().value("Motd").toString(),
        rooms
    }));
}

void Client::doSynchronize(Synchronize d)
{
    if (id_room.isEmpty())
    {
        close("Client requested synchronization without being in any room");
        return;
    }

    QSqlQuery query(Database::get());
    query.prepare("SELECT * FROM ARCHIVE"
                  " WHERE ID >"
                  " ("
                  " SELECT ID FROM ARCHIVE"
                  " WHERE ID_MESSAGE = ?"
                  " )"
                  " AND ID_ROOM = ?");
    query.addBindValue(d.id_message);
    query.addBindValue(id_room);

    if (!query.exec())
    {
        Server::error(query.lastError().text());
    }

    while (query.next())
    {
        sendOne(PacketType::Message, QVariant::fromValue(
                    Message
        {
            query.value(1).toLongLong(),
            query.value(2).toByteArray(),
            query.value(4).toString(),
            query.value(5).toString()
        }));
    }
}

void Client::doMessage(Message d)
{
    if (id_room.isEmpty())
    {
        close("Client sent a message without being in any room");
        return;
    }

    d.timestamp = QDateTime::currentSecsSinceEpoch();
    d.id_sender = id;

    QSqlQuery query(Database::get());
    query.prepare("INSERT INTO ARCHIVE (TIMESTAMP, ID_MESSAGE, ID_ROOM, ID_SENDER, CONTENT)"
                  " VALUES (?, ?, ?, ?, ?)");
    query.addBindValue(d.timestamp);
    query.addBindValue(d.id);
    query.addBindValue(id_room);
    query.addBindValue(d.id_sender);
    query.addBindValue(d.content);

    if (!query.exec())
    {
        if (query.lastError().nativeErrorCode() == "23505")
        {
            close("Client sent a message, but another one with the same ID was found in the database");
            return;
        }

        Server::error(query.lastError().text());
    }

    for (const auto &participant : Server::participants.values(id_room))
    {
        if (participant == this)
        {
            continue;
        }

        QMetaObject::invokeMethod(participant, "sendOne",
                                  Q_ARG(PacketType, PacketType::Message),
                                  Q_ARG(QVariant, QVariant::fromValue(d)));
    }
}

void Client::doRtRoom(RtRoom d)
{
    switch (d.request)
    {
    case RtRoom::Join:
    {
        QSqlQuery query(Database::get());
        query.prepare("SELECT 1"
                      " FROM ROOMS"
                      " WHERE ID = ?");
        query.addBindValue(d.id);

        if (!query.exec())
        {
            Server::error(query.lastError().text());
        }

        if (!query.next())
        {
            close("Client wants to enter a non-existent room");
            return;
        }

        if (!id_room.isEmpty())
        {
            leaveRoom();
        }

        id_room = d.id;

        sendOne(PacketType::ReRoom, QVariant::fromValue(
                    ReRoom
        {
            ReRoom::Joined
        }));

        QVector<QByteArray> uniqueUsers;

        auto notify = true;

        for (const auto &client : Server::connected.values(id))
        {
            if (client == this)
            {
                continue;
            }

            if (Server::participants.contains(id_room, client))
            {
                notify = false;
                break;
            }
        }

        for (const auto &participant : Server::participants.values(id_room))
        {
            if (participant->id == id)
            {
                continue;
            }

            if (!uniqueUsers.contains(participant->id))
            {
                uniqueUsers.append(participant->id);

                sendOne(PacketType::UserState, QVariant::fromValue(
                            UserState
                {
                    participant->id,
                    UserState::Joined
                }));
            }

            if (!notify)
            {
                continue;
            }

            QMetaObject::invokeMethod(participant, "sendOne",
                                      Q_ARG(PacketType, PacketType::UserState),
                                      Q_ARG(QVariant, QVariant::fromValue(
                                                UserState
            {
                id,
                UserState::Joined
            })));
        }

        Server::participants.insertMulti(d.id, this);
    }
    break;

    case RtRoom::Leave:
    {
        if (id_room.isEmpty())
        {
            close("Client wants to leave the room without being in any room");
            return;
        }

        leaveRoom();

        sendOne(PacketType::ReRoom, QVariant::fromValue(
                    ReRoom
        {
            ReRoom::Left
        }));
    }
    break;
    }
}

void Client::doRtUpload(RtUpload d)
{
    if (usershare.contains(d.id))
    {
        close("Client wants to start the file transfer, but another one with the same ID was found");
        return;
    }

    QSharedPointer<File> file(new File(QString("usershare/%1").arg(QString(d.id.toHex()))));

    switch (d.request)
    {
    case RtUpload::Receive:
    {
        if (!file->exists())
        {
            sendOne(PacketType::ReUpload, QVariant::fromValue(
                        ReUpload
            {
                d.id,
                ReUpload::ErrorOccurred,
                ReUpload::NotFound
            }));
            return;
        }

        if (!file->open(QIODevice::ReadOnly))
        {
            sendOne(PacketType::ReUpload, QVariant::fromValue(
                        ReUpload
            {
                d.id,
                ReUpload::ErrorOccurred,
                ReUpload::InternalServerError
            }));
            return;
        }

        if (file->size() != d.size)
        {
            sendOne(PacketType::ReUpload, QVariant::fromValue(
                        ReUpload
            {
                d.id,
                ReUpload::ErrorOccurred,
                ReUpload::BadRequest
            }));
            return;
        }

        sendOne(PacketType::ReUpload, QVariant::fromValue(
                    ReUpload
        {
            d.id,
            ReUpload::ReadyWrite,
            ReUpload::NoError
        }));
    }
    break;

    case RtUpload::Transmit:
    {
        if (d.size < 1)
        {
            close("Client wants to send a file with the wrong size");
            return;
        }

        if (file->exists())
        {
            close("Client wants to send the file, but another one with the same ID was found");
            return;
        }

        if (!file->open(QIODevice::WriteOnly))
        {
            sendOne(PacketType::ReUpload, QVariant::fromValue(
                        ReUpload
            {
                d.id,
                ReUpload::ErrorOccurred,
                ReUpload::InternalServerError
            }));
            return;
        }

        if (!file->resize(d.size))
        {
            sendOne(PacketType::ReUpload, QVariant::fromValue(
                        ReUpload
            {
                d.id,
                ReUpload::ErrorOccurred,
                ReUpload::InternalServerError
            }));
            return;
        }

        sendOne(PacketType::ReUpload, QVariant::fromValue(
                    ReUpload
        {
            d.id,
            ReUpload::ReadyRead,
            ReUpload::NoError
        }));
    }
    break;
    }

    usershare.insert(d.id, file);
}

void Client::doUpload(Upload d)
{
    if (!usershare.contains(d.id))
    {
        close("Client sent data related to non-existent file transfer");
        return;
    }

    auto file = usershare.value(d.id);

    if (d.chunkdata.isEmpty())
    {
        close("Client sent an empty data chunk");
        return;
    }

    if (d.chunkdata.size() > file->getRemained())
    {
        close("Client sent more data than required");
        return;
    }

    file->write(d.chunkdata);

    if (file->atEnd())
    {
        usershare.remove(d.id);

        sendOne(PacketType::UploadState, QVariant::fromValue(
                    UploadState
        {
            d.id,
            UploadState::Completed
        }));
    }
    else
    {
        sendOne(PacketType::UploadState, QVariant::fromValue(
                    UploadState
        {
            d.id,
            UploadState::Next
        }));
    }
}

void Client::doUploadState(UploadState d)
{
    if (!usershare.contains(d.id))
    {
        close("Client sent data related to non-existent file transfer");
        return;
    }

    auto file = usershare.value(d.id);

    switch (d.state)
    {
    case UploadState::Next:
    {
        if (file->atEnd())
        {
            close("Client requested more data than required");
            return;
        }

        sendOne(PacketType::Upload, QVariant::fromValue(
                    Upload
        {
            d.id,
            file->read()
        }));
    }
    break;

    case UploadState::Canceled:
    case UploadState::Completed:
    {
        usershare.remove(d.id);
    }
    break;
    }
}

void Client::doPong(Ping d)
{
    if (d.timestamp != pingTimestamp)
    {
        close("Client ping timestamp is invalid");
        return;
    }

    if (disconnectTimer->isActive())
    {
        disconnectTimer->stop();
    }

    pingTimer->start();
}

void Client::leaveRoom()
{
    Server::participants.remove(id_room, this);

    auto notify = true;

    for (const auto &client : Server::connected.values(id))
    {
        if (client == this)
        {
            continue;
        }

        if (Server::participants.contains(id_room, client))
        {
            notify = false;
            break;
        }
    }

    if (notify)
    {
        for (const auto &participant : Server::participants.values(id_room))
        {
            if (participant->id == id)
            {
                continue;
            }

            QMetaObject::invokeMethod(participant, "sendOne",
                                      Q_ARG(PacketType, PacketType::UserState),
                                      Q_ARG(QVariant, QVariant::fromValue(
                                                UserState
            {
                id,
                UserState::Left
            })));
        }
    }

    id_room.clear();
}

void Client::sendOne(PacketType type, const QVariant &v)
{
    if (interruptionRequested)
    {
        return;
    }

    writing = true;

    QByteArray out;
    QVector<quint8> crypto[2];

    if (!v.isNull())
    {
        QDataStream ds(&out, QIODevice::WriteOnly);
        v.save(ds);

        if (encryption)
        {
            crypto[0].resize(enc.DigestSize());
            crypto[1].resize(enc.DefaultIVLength());

            enc.GetNextIV(rng, crypto[1].data());
            enc.SetKeyWithIV(shared_secret.constData(),
                             shared_secret.size(),
                             crypto[1].constData(),
                             crypto[1].size());
            enc.EncryptAndAuthenticate(reinterpret_cast<quint8 *>(out.data()),
                                       crypto[0].data(),
                                       crypto[0].size(),
                                       crypto[1].constData(),
                                       crypto[1].size(),
                                       nullptr,
                                       0,
                                       reinterpret_cast<const quint8 *>(out.constData()), out.size());
        }
    }

    QByteArray t;
    QDataStream ds(&t, QIODevice::WriteOnly);

    ds << quint8(type) << quint16(out.size());

    if (!v.isNull())
    {
        if (!shared_secret.empty())
        {
            ds.writeRawData(reinterpret_cast<const char *>(crypto[0].constData()), crypto[0].size());
            ds.writeRawData(reinterpret_cast<const char *>(crypto[1].constData()), crypto[1].size());
        }

        ds.writeRawData(out.constData(), out.size());
    }

    socket->write(t.constData(), t.size());
    socket->flush();

    writing = false;
    emit written();
}
