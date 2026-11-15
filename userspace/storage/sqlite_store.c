#include "storage.h"

int storage_count_alerts(struct kalatrace_storage *storage, uint64_t *out_count)
{
    if (storage == NULL || storage->db == NULL || out_count == NULL) {
        return SQLITE_MISUSE;
    }

    const char *sql = "SELECT COUNT(*) FROM alerts;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return rc;
    }

    uint64_t result = (uint64_t)sqlite3_column_int64(stmt, 0);

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return rc;
    }

    *out_count = result;

    return SQLITE_OK;
}

int storage_count_alerts_by_severity(struct kalatrace_storage *storage, const char *severity, uint64_t *out_count)
{
    if (storage == NULL || storage->db == NULL || severity == NULL || out_count == NULL) {
        return SQLITE_MISUSE;
    }

    const char *sql = "SELECT COUNT(*) FROM alerts WHERE severity = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 1, severity, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return rc;
    }

    uint64_t result = (uint64_t)sqlite3_column_int64(stmt, 0);

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return rc;
    }

    *out_count = result;

    return SQLITE_OK;
}
