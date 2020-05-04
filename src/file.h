#ifndef FILE_H
#define FILE_H

#include <QFile>

#include <string>

class File : public QFile
{
    Q_OBJECT
public:
    explicit File(const QString &);
    ~File();

    qint64 getRemained() const;

    QByteArray read();
    void write(const QByteArray &);
};

#endif // FILE_H
