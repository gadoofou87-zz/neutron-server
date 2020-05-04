#ifndef THREAD_H
#define THREAD_H

#include <QHash>
#include <QThread>
#include <QVector>

class Thread
{
public:
    static void prepare();

    static void attach(QObject *);
    static QThread *get();

private:
    static QHash<QThread *, int> attached;
    static QVector<QThread *> pool;
};

#endif // THREAD_H
