#include "thread.h"

#include <QCoreApplication>

QHash<QThread *, int> Thread::attached;
QVector<QThread *> Thread::pool;

void Thread::prepare()
{
    for (int i = 0; i < QThread::idealThreadCount(); i++)
    {
        auto *thread = new QThread;

        attached.insert(thread, 0);
        pool.append(thread);
    }
}

void Thread::attach(QObject *object)
{
    attached[object->thread()]++;

    QObject::connect(object, &QObject::destroyed, [ = ]
    {
        attached[object->thread()]--;
    });
}

QThread *Thread::get()
{
    QThread *thread = nullptr;
    int min = -1;

    for (auto it = attached.begin(); it != attached.end(); it++)
    {
        if (min > it.value() || min == -1)
        {
            thread = it.key();
            min = it.value();
        }

        if (min == 0)
        {
            break;
        }
    }

    if (!thread->isRunning())
    {
        thread->start();

        QObject::connect(qApp, &QCoreApplication::aboutToQuit, [ = ]
        {
            thread->quit();
            thread->wait();
        });
    }

    return thread;
}
