#ifndef CLIENT_H
#define CLIENT_H

#include "packet.h"

#include <QDataStream>
#include <QHash>
#include <QSharedPointer>
#include <QTcpSocket>
#include <QTimer>

#include <cryptopp/chachapoly.h>
#include <cryptopp/osrng.h>

class File;
class Client : public QObject
{
    Q_OBJECT
public:
    explicit Client();
    ~Client();

public slots:
    void run(QTcpSocket *);
    void close(QString = {});

    void sendOne(PacketType, const QVariant & = {});

signals:
    void read();
    void written();

private slots:
    void onDisconnected();
    void onReadyRead();

private:
    QTcpSocket *socket;
    QDataStream stream;

    QByteArray id;
    QByteArray id_room;

    bool interruptionRequested;
    bool reading;
    bool writing;

    bool encryption;
    QVector<quint8> public_key;
    QVector<quint8> secret_key;
    QVector<quint8> shared_secret;

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::XChaCha20Poly1305::Decryption dec;
    CryptoPP::XChaCha20Poly1305::Encryption enc;

    QHash<QByteArray, QSharedPointer<File>> usershare;

    QTimer *disconnectTimer;
    QTimer *pingTimer;
    qint64 pingTimestamp;

    void doHandshake(ClientKeyExchange);
    void doRtAuthorization(RtAuthorization);
    void doSynchronize(Synchronize);
    void doMessage(Message);
    void doRtRoom(RtRoom);
    void doRtUpload(RtUpload);
    void doUpload(Upload);
    void doUploadState(UploadState);
    void doPong(Ping);

    void leaveRoom();
};

#endif // CLIENT_H
