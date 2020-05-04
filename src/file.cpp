#include "file.h"
#include "server.h"

static constexpr qint64 PAGE_SIZE = 32768;

File::File(const QString &name) : QFile(name)
{
}

File::~File()
{
    if (isOpen())
    {
        if (isWritable())
        {
            if (!atEnd())
            {
                remove();
            }
        }

        close();
    }
}

qint64 File::getRemained() const
{
    return size() - pos();
}

QByteArray File::read()
{
    QByteArray data;
    data.resize(qMin(getRemained(), PAGE_SIZE));

    if (qint64(data.size()) != QIODevice::read(data.data(), data.size()))
    {
        Server::error("Error reading from file");
    }

    return data;
}

void File::write(const QByteArray &data)
{
    if (qint64(data.size()) != QIODevice::write(data.constData(), data.size()))
    {
        Server::error("Error writing to file");
    }
}
