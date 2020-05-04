#include "database.h"

QHash<QThread *, QSqlDatabase> Database::pool;

QSqlDatabase Database::get(QThread *thread)
{
    QSqlDatabase db;

    if (pool.contains(thread))
    {
        db = pool.value(thread);
    }
    else
    {
        db = QSqlDatabase::cloneDatabase(QSqlDatabase::defaultConnection,
                                         QString::number(pool.size()));
        db.open();

        pool.insert(thread, db);
    }

    return db;
}
