#include "storage.h"

int storage_rollback_transaction(struct kalatrace_storage *storage) {
    if (storage == NULL || storage->db == NULL)
        return SQLITE_MISUSE;

    if (sqlite3_get_autocommit(storage->db)) {
        return SQLITE_OK;
    }

    int rc = non_row_exec_sql(storage->db, "ROLLBACK;");

    if (rc != SQLITE_OK) {
        fprintf(stderr, "ROLLBACK failed: %s (rc=%d)\n", sqlite3_errmsg(storage->db), sqlite3_extended_errcode(storage->db));

        if (sqlite3_get_autocommit(storage->db)) {
            fprintf(stderr, "Transaction is no longer active\n");
        } else {
            fprintf(stderr, "CRITICAL: Transaction is still active (rc=%d)\n", rc);
        }

        return rc;
    }

    return SQLITE_OK;
}
