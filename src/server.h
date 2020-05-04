#ifndef SERVER_H
#define SERVER_H

#include <QMultiHash>
#include <QSettings>

class Client;
class Server
{
public:
    explicit Server();

    static const QVector<quint8> &getPublicKey();
    static const QVector<quint8> &getSecretKey();

    static QSettings &getSettings();

    static QMultiHash<QByteArray, Client *> connected;
    static QMultiHash<QByteArray, Client *> participants;

    [[ noreturn ]] static void error(const QString &);

private:
    static QByteArray id;
    static QVector<quint8> public_key;
    static QVector<quint8> secret_key;

    static QSettings settings;

    static void initCrypto();
    static void initDatabase();
};

#endif // SERVER_H
