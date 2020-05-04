#include "packet.h"

#include <QDataStream>

QDataStream &operator<<(QDataStream &out, const ServerKeyExchange &d)
{
    out << d.public_key[0]
        << d.public_key[1]
        << d.signature;
    return out;
};

QDataStream &operator>>(QDataStream &in, ServerKeyExchange &d)
{
    in >> d.public_key[0]
       >> d.public_key[1]
       >> d.signature;
    return in;
}

QDataStream &operator<<(QDataStream &out, const ClientKeyExchange &d)
{
    out << d.ciphertext;
    return out;
}

QDataStream &operator>>(QDataStream &in, ClientKeyExchange &d)
{
    in >> d.ciphertext;
    return in;
}

QDataStream &operator<<(QDataStream &out, const RtAuthorization &d)
{
    out << d.username
        << d.password
        << d.request;
    return out;
}

QDataStream &operator>>(QDataStream &in, RtAuthorization &d)
{
    in >> d.username
       >> d.password
       >> d.request;
    return in;
}

QDataStream &operator<<(QDataStream &out, const ReAuthorization &d)
{
    out << d.response
        << d.error;
    return out;
}

QDataStream &operator>>(QDataStream &in, ReAuthorization &d)
{
    in >> d.response
       >> d.error;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Room &d)
{
    out << d.id
        << d.name;
    return out;
}

QDataStream &operator>>(QDataStream &in, Room &d)
{
    in >> d.id
       >> d.name;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Established &d)
{
    out << d.name
        << d.motd
        << d.rooms;
    return out;
}

QDataStream &operator>>(QDataStream &in, Established &d)
{
    in >> d.name
       >> d.motd
       >> d.rooms;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Synchronize &d)
{
    out << d.id_message;
    return out;
}

QDataStream &operator>>(QDataStream &in, Synchronize &d)
{
    in >> d.id_message;
    return in;
}

QDataStream &operator<<(QDataStream &out, const UserState &d)
{
    out << d.id
        << d.state;
    return out;
}

QDataStream &operator>>(QDataStream &in, UserState &d)
{
    in >> d.id
       >> d.state;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Message &d)
{
    out << d.timestamp
        << d.id
        << d.id_sender
        << d.content;
    return out;
}

QDataStream &operator>>(QDataStream &in, Message &d)
{
    in >> d.timestamp
       >> d.id
       >> d.id_sender
       >> d.content;
    return in;
}

QDataStream &operator<<(QDataStream &out, const RtRoom &d)
{
    out << d.id
        << d.request;
    return out;
}

QDataStream &operator>>(QDataStream &in, RtRoom &d)
{
    in >> d.id
       >> d.request;
    return in;
}

QDataStream &operator<<(QDataStream &out, const ReRoom &d)
{
    out << d.response;
    return out;
}

QDataStream &operator>>(QDataStream &in, ReRoom &d)
{
    in >> d.response;
    return in;
}

QDataStream &operator<<(QDataStream &out, const RtUpload &d)
{
    out << d.id
        << d.size
        << d.request;
    return out;
}

QDataStream &operator>>(QDataStream &in, RtUpload &d)
{
    in >> d.id
       >> d.size
       >> d.request;
    return in;
}

QDataStream &operator<<(QDataStream &out, const ReUpload &d)
{
    out << d.id
        << d.response
        << d.error;
    return out;
}

QDataStream &operator>>(QDataStream &in, ReUpload &d)
{
    in >> d.id
       >> d.response
       >> d.error;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Upload &d)
{
    out << d.id
        << d.chunkdata;
    return out;
}

QDataStream &operator>>(QDataStream &in, Upload &d)
{
    in >> d.id
       >> d.chunkdata;
    return in;
}

QDataStream &operator<<(QDataStream &out, const UploadState &d)
{
    out << d.id
        << d.state;
    return out;
}

QDataStream &operator>>(QDataStream &in, UploadState &d)
{
    in >> d.id
       >> d.state;
    return in;
}

QDataStream &operator<<(QDataStream &out, const Ping &d)
{
    out << d.timestamp;
    return out;
}

QDataStream &operator>>(QDataStream &in, Ping &d)
{
    in >> d.timestamp;
    return in;
}
