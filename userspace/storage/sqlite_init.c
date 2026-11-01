#include "storage.h"

int storage_init(struct kalatrace_storage *storage, const char *db_path) {
    if (db_path == NULL || storage == NULL) {
        return SQLITE_MISUSE;
    }

    storage->db = NULL;

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    
    if (sqlite3_open_v2(db_path, &storage->db, flags, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(storage->db));
        if (storage->db) {
            sqlite3_close(storage->db);
            storage->db = NULL;
        }
        return SQLITE_ERROR;
    }
    return 0;
}