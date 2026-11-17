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

int storage_insert_alert(struct kalatrace_storage *storage, struct kalatrace_alert **alerts, const int count_alerts)
{
    if (storage == NULL || storage->db == NULL || alerts == NULL || count_alerts <= 0) {
        return SQLITE_MISUSE;
    }

    const char *sql = 
        "INSERT INTO alerts (timestamp_ns, rule_id, severity, message, event_type, pid, ppid, uid, gid, comm, parent_comm, path, exe_path) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return rc;
    }
    
    rc = non_row_exec_sql(storage->db, "BEGIN IMMEDIATE;");
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return rc;
    }

    for (int i = 0; i < count_alerts; i++) {
        struct kalatrace_alert *alert = alerts[i];

        if (alert->timestamp_ns > INT64_MAX) {
            fprintf(stderr, "Timestamp exceeds INT64_MAX: %" PRIu64 "\n", alert->timestamp_ns);
            rc = non_row_exec_sql(storage->db, "ROLLBACK;");
            if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to rollback transaction after timestamp error: %s\n", sqlite3_errmsg(storage->db));
            }
            rc = sqlite3_finalize(stmt);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to finalize statement after timestamp error: %s\n", sqlite3_errmsg(storage->db));
            }
            return SQLITE_TOOBIG;
        }

        rc = sqlite3_bind_int64(stmt, 1, alert->timestamp_ns);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 2, alert->rule_id, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 3, alert->severity, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 4, alert->message, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 5, alert->event_type);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 6, alert->pid);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 7, alert->ppid);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 8, alert->uid);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 9, alert->gid);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 10, alert->comm, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 11, alert->parent_comm, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 12, alert->path, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 13, alert->exe_path, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            goto rollback;
        }

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "Failed to insert alert: %" PRIu64 " (rc=%d): %s\n", alert->timestamp_ns, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }

        rc = sqlite3_reset(stmt);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to reset statement after inserting alert: %" PRIu64 " (rc=%d): %s\n", alert->timestamp_ns, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }

        rc = sqlite3_clear_bindings(stmt);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to clear bindings after inserting alert: %" PRIu64 " (rc=%d): %s\n", alert->timestamp_ns, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    }

    rc = non_row_exec_sql(storage->db, "COMMIT;");
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to commit transaction after inserting alerts (rc=%d): %s\n", rc, sqlite3_errmsg(storage->db));
        rc = non_row_exec_sql(storage->db, "ROLLBACK;");
        return rc;
    }

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to finalize statement after inserting alerts (rc=%d): %s\n", rc, sqlite3_errmsg(storage->db));
        return rc;
    }

    return SQLITE_OK;

    rollback:
        fprintf(stderr, "Error in storage_insert_alert: %s (rc=%d)\n", sqlite3_errmsg(storage->db), rc);
        non_row_exec_sql(storage->db, "ROLLBACK;");
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to finalize statement after rollback: %s\n", sqlite3_errmsg(storage->db));
        }
        return rc;
}
