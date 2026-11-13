#include "storage.h"

static int open_database(const char* database_path, sqlite3 **db) 
{
    int flags = 
        SQLITE_OPEN_READWRITE |
        SQLITE_OPEN_CREATE |
        SQLITE_OPEN_FULLMUTEX |
        SQLITE_OPEN_PRIVATECACHE |
        SQLITE_OPEN_NOFOLLOW;

    int rc = sqlite3_open_v2(database_path, db, flags, NULL);
    if (rc != SQLITE_OK) {
        if (*db != NULL) {
            int close_rc = sqlite3_close(*db);
            if (close_rc != SQLITE_OK) {
                fprintf(stderr, "Failed to close database after open failure: %s\n", sqlite3_errmsg(*db));
                return close_rc;
            }
            *db = NULL;
        }
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    }
    return SQLITE_OK;
}

static int enable_wal(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;

    const char *sql = "PRAGMA journal_mode=WAL;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare WAL pragma: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "Failed to set WAL mode: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    const unsigned char *mode = sqlite3_column_text(stmt, 0);
    if (mode == NULL || strcmp((const char *)mode, "wal") != 0) {
        fprintf(stderr, "WAL mode not enabled: %s\n", mode != NULL ? (const char *)mode : "(null)");
        sqlite3_finalize(stmt);
        return SQLITE_ERROR;
    }

    printf("journal_mode: %s.\n", mode);

    rc = sqlite3_finalize(stmt);
    
    return rc;
}

static int non_row_exec_sql(sqlite3 *db, const char *sql)
{
    char *error_message = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error_message);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message != NULL ? error_message : sqlite3_errmsg(db));
        sqlite3_free(error_message);
        return rc;
    }
    return SQLITE_OK;
}

static int configure_database(sqlite3 *db) 
{   

    int rc = sqlite3_busy_timeout(db, 5000);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set busy timeout: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    rc = sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set defensive mode: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    rc = sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set trusted schema: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    rc = enable_wal(db);
    if (rc != SQLITE_OK) {
        return rc;
    }

    const char *pragmas = 
        "PRAGMA synchronous=FULL;"
        "PRAGMA foreign_keys=ON;"
        "PRAGMA locking_mode=NORMAL;"
        "PRAGMA trusted_schema=OFF;"
        "PRAGMA wal_autocheckpoint=1000;";

    rc = non_row_exec_sql(db, pragmas);
    if (rc != SQLITE_OK) {
        return rc;
    }

    return SQLITE_OK;
}

static int create_schema(sqlite3 *db)
{
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS alerts ("
        "    id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    timestamp_ns INTEGER NOT NULL,"
        "    rule_id     TEXT NOT NULL,"
        "    severity    TEXT NOT NULL,"
        "    message     TEXT NOT NULL,"
        "    event_type  INTEGER NOT NULL,"
        "    pid         INTEGER NOT NULL,"
        "    ppid        INTEGER NOT NULL,"
        "    uid         INTEGER NOT NULL,"
        "    gid         INTEGER NOT NULL,"
        "    comm        TEXT NOT NULL,"
        "    parent_comm TEXT NOT NULL,"
        "    path        TEXT NOT NULL,"
        "    exe_path    TEXT NOT NULL"
        ");";
    return non_row_exec_sql(db, sql);
}

int storage_init(struct kalatrace_storage *storage, const char *db_path) {
    if (storage == NULL) {
        fprintf(stderr, "Storage pointer is NULL\n");
        return SQLITE_MISUSE;
    }
    
    if (db_path == NULL) {
        fprintf(stderr, "Database path is NULL\n");
        return SQLITE_ERROR;
    }

    int rc = open_database(db_path, &storage->db);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = configure_database(storage->db);
    if (rc != SQLITE_OK) {
        int close_rc = sqlite3_close(storage->db);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close database after configuration failure: %s\n", sqlite3_errmsg(storage->db));
            return close_rc;
        }
        storage->db = NULL;
        return rc;
    }

    rc = create_schema(storage->db);
    if (rc != SQLITE_OK) {
        int close_rc = sqlite3_close(storage->db);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close database after schema creation failure: %s\n", sqlite3_errmsg(storage->db));
            return close_rc;
        }
        storage->db = NULL;
        return rc;
    }

    printf("Database initialized successfully at %s.\n", db_path);

    return SQLITE_OK;
}