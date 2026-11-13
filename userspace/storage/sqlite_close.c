#include "storage.h"

int storage_close(struct kalatrace_storage *storage) {
    if (storage == NULL || storage->db == NULL) {
        return SQLITE_MISUSE;
    }

    int rc = sqlite3_close(storage->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close database: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    storage->db = NULL;
    return SQLITE_OK;
}