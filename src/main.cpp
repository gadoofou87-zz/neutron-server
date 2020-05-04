#include "packet.h"
#include "server.h"

#include <QCoreApplication>

#include <csignal>

void signalHandler(int signum)
{
    if (signum == SIGINT)
    {
        qApp->quit();
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signalHandler);

    qRegisterMetaTypeStreamOperators<ServerKeyExchange>("ServerKeyExchange");
    qRegisterMetaTypeStreamOperators<ClientKeyExchange>("ClientKeyExchange");
    qRegisterMetaTypeStreamOperators<RtAuthorization>("RtAuthorization");
    qRegisterMetaTypeStreamOperators<ReAuthorization>("ReAuthorization");
    qRegisterMetaTypeStreamOperators<Room>("Room");
    qRegisterMetaTypeStreamOperators<Established>("Established");
    qRegisterMetaTypeStreamOperators<Synchronize>("Synchronize");
    qRegisterMetaTypeStreamOperators<UserState>("UserState");
    qRegisterMetaTypeStreamOperators<Message>("Message");
    qRegisterMetaTypeStreamOperators<RtRoom>("RtRoom");
    qRegisterMetaTypeStreamOperators<ReRoom>("ReRoom");
    qRegisterMetaTypeStreamOperators<RtUpload>("RtUpload");
    qRegisterMetaTypeStreamOperators<ReUpload>("ReUpload");
    qRegisterMetaTypeStreamOperators<Upload>("Upload");
    qRegisterMetaTypeStreamOperators<UploadState>("UploadState");
    qRegisterMetaTypeStreamOperators<Ping>("Ping");

    QCoreApplication a(argc, argv);
    Server();
    return QCoreApplication::exec();
}
