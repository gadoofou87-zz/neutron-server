#ifndef PACKET_H
#define PACKET_H

#include <QMetaType>
#include <QVector>

enum class PacketType
{
    Handshake,
    RtAuthorization,
    ReAuthorization,
    Established,
    Synchronize,
    UserState,
    Message,
    RtRoom,
    ReRoom,
    RtUpload,
    ReUpload,
    Upload,
    UploadState,
    Ping,
    Pong
};

struct ServerKeyExchange
{
    QVector<quint8> public_key[2];
    QVector<quint8> signature;
};
QDataStream &operator<<(QDataStream &, const ServerKeyExchange &);
QDataStream &operator>>(QDataStream &, ServerKeyExchange &);

struct ClientKeyExchange
{
    QVector<quint8> ciphertext;
};
QDataStream &operator<<(QDataStream &, const ClientKeyExchange &);
QDataStream &operator>>(QDataStream &, ClientKeyExchange &);

struct RtAuthorization
{
    enum Request
    {
        Signin,
        Signup
    };
    QByteArray username;
    QByteArray password;
    Request request;
};
QDataStream &operator<<(QDataStream &, const RtAuthorization &);
QDataStream &operator>>(QDataStream &, RtAuthorization &);

struct ReAuthorization
{
    enum Response
    {
        ErrorOccurred,
        Authorized
    };
    enum Error
    {
        NoError,
        InvalidUsername,
        InvalidPassword,
        UserExists
    };
    Response response;
    Error error;
};
QDataStream &operator<<(QDataStream &, const ReAuthorization &);
QDataStream &operator>>(QDataStream &, ReAuthorization &);

struct Room
{
    QByteArray id;
    QString name;
};
QDataStream &operator<<(QDataStream &, const Room &);
QDataStream &operator>>(QDataStream &, Room &);

struct Established
{
    QString name;
    QString motd;
    QVector<Room> rooms;
};
QDataStream &operator<<(QDataStream &, const Established &);
QDataStream &operator>>(QDataStream &, Established &);

struct Synchronize
{
    QByteArray id_message;
};
QDataStream &operator<<(QDataStream &, const Synchronize &);
QDataStream &operator>>(QDataStream &, Synchronize &);

struct UserState
{
    enum State
    {
        Joined,
        Left
    };
    QByteArray id;
    State state;
};
QDataStream &operator<<(QDataStream &, const UserState &);
QDataStream &operator>>(QDataStream &, UserState &);

struct Message
{
    qint64 timestamp;
    QByteArray id;
    QString id_sender;
    QString content;
};
QDataStream &operator<<(QDataStream &, const Message &);
QDataStream &operator>>(QDataStream &, Message &);

struct RtRoom
{
    enum Request
    {
        Join,
        Leave
    };
    QByteArray id;
    Request request;
};
QDataStream &operator<<(QDataStream &, const RtRoom &);
QDataStream &operator>>(QDataStream &, RtRoom &);

struct ReRoom
{
    enum Response
    {
        Joined,
        Left
    };
    Response response;
};
QDataStream &operator<<(QDataStream &, const ReRoom &);
QDataStream &operator>>(QDataStream &, ReRoom &);

struct RtUpload
{
    enum Request
    {
        Receive,
        Transmit
    };
    QByteArray id;
    qint64 size;
    Request request;
};
QDataStream &operator<<(QDataStream &, const RtUpload &);
QDataStream &operator>>(QDataStream &, RtUpload &);

struct ReUpload
{
    enum Response
    {
        ErrorOccurred,
        ReadyRead,
        ReadyWrite
    };
    enum Error
    {
        NoError,
        InternalServerError,
        BadRequest,
        NotFound
    };
    QByteArray id;
    Response response;
    Error error;
};
QDataStream &operator<<(QDataStream &, const ReUpload &);
QDataStream &operator>>(QDataStream &, ReUpload &);

struct Upload
{
    QByteArray id;
    QByteArray chunkdata;
};
QDataStream &operator<<(QDataStream &, const Upload &);
QDataStream &operator>>(QDataStream &, Upload &);

struct UploadState
{
    enum State
    {
        Next,
        Canceled,
        Completed
    };
    QByteArray id;
    State state;
};
QDataStream &operator<<(QDataStream &, const UploadState &);
QDataStream &operator>>(QDataStream &, UploadState &);

struct Ping
{
    qint64 timestamp;
};
QDataStream &operator<<(QDataStream &, const Ping &);
QDataStream &operator>>(QDataStream &, Ping &);

Q_DECLARE_METATYPE(PacketType)
Q_DECLARE_METATYPE(ServerKeyExchange)
Q_DECLARE_METATYPE(ClientKeyExchange)
Q_DECLARE_METATYPE(RtAuthorization)
Q_DECLARE_METATYPE(ReAuthorization)
Q_DECLARE_METATYPE(Room)
Q_DECLARE_METATYPE(Established)
Q_DECLARE_METATYPE(Synchronize)
Q_DECLARE_METATYPE(UserState)
Q_DECLARE_METATYPE(Message)
Q_DECLARE_METATYPE(RtRoom)
Q_DECLARE_METATYPE(ReRoom)
Q_DECLARE_METATYPE(RtUpload)
Q_DECLARE_METATYPE(ReUpload)
Q_DECLARE_METATYPE(Upload)
Q_DECLARE_METATYPE(UploadState)
Q_DECLARE_METATYPE(Ping)

#endif // PACKET_H
