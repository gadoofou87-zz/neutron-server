#ifndef DATABASE_H
#define DATABASE_H

#include <QHash>
#include <QSqlDatabase>
#include <QThread>

class Database
{
public:
    static QSqlDatabase get(QThread * = QThread::currentThread());

private:
    static QHash<QThread *, QSqlDatabase> pool;
};

#endif // DATABASE_H
