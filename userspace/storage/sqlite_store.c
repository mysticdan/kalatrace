#include "storage.h"

int storage_count_alerts(struct kalatrace_storage *storage, uint64_t *out_count)
{
    if (storage == NULL || storage->db == NULL || storage->unusable || out_count == NULL) {
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
    if (storage == NULL || storage->db == NULL || storage->unusable || severity == NULL || out_count == NULL) {
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
    if (storage == NULL || storage->db == NULL || storage->unusable || alerts == NULL || count_alerts <= 0) {
        return SQLITE_MISUSE;
    }

    for (int i = 0; i < count_alerts; i++) {
        if (alerts[i] == NULL) {
            return SQLITE_MISUSE;
        }
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
            
            rc = SQLITE_TOOBIG;
            goto rollback;
        }

        rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)alert->timestamp_ns);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind timestamp for alert: %" PRIu64 " (rc=%d): %s\n", alert->timestamp_ns, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 2, alert->rule_id, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind rule_id for alert: %s (rc=%d): %s\n", alert->rule_id, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 3, alert->severity, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind severity for alert: %s (rc=%d): %s\n", alert->severity, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 4, alert->message, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind message for alert: %s (rc=%d): %s\n", alert->message, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 5, alert->event_type);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind event_type for alert: %u (rc=%d): %s\n", alert->event_type, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 6, alert->pid);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind pid for alert: %u (rc=%d): %s\n", alert->pid, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 7, alert->ppid);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind ppid for alert: %u (rc=%d): %s\n", alert->ppid, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 8, alert->uid);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind uid for alert: %u (rc=%d): %s\n", alert->uid, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_int64(stmt, 9, alert->gid);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind gid for alert: %u (rc=%d): %s\n", alert->gid, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 10, alert->comm, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind comm for alert: %s (rc=%d): %s\n", alert->comm, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 11, alert->parent_comm, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind parent_comm for alert: %s (rc=%d): %s\n", alert->parent_comm, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 12, alert->path, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind path for alert: %s (rc=%d): %s\n", alert->path, rc, sqlite3_errmsg(storage->db));
            goto rollback;
        }
    
        rc = sqlite3_bind_text(stmt, 13, alert->exe_path, -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to bind exe_path for alert: %s (rc=%d): %s\n", alert->exe_path, rc, sqlite3_errmsg(storage->db));
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

    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) {
        goto rollback;
    }

    rc = non_row_exec_sql(storage->db, "COMMIT;");
    if (rc != SQLITE_OK) {
        goto rollback;
    }
    return SQLITE_OK;

rollback:
    /* Preserve the operation error independently of all cleanup results. */
    fprintf(stderr, "Error in storage_insert_alert: %s (rc=%d)\n", sqlite3_errstr(rc), rc);
    int finalize_rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (finalize_rc != SQLITE_OK) {
        fprintf(stderr, "Finalize during cleanup: %s (rc=%d)\n", sqlite3_errstr(finalize_rc), finalize_rc);
    }
    int rollback_rc = storage_rollback_transaction(storage);
    if (rollback_rc != SQLITE_OK) {
        storage->unusable = true;
        fprintf(stderr, "Rollback during cleanup failed (rc=%d)\n", rollback_rc);
        int close_rc = storage_close(storage);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Storage remains unusable: close failed (rc=%d)\n", close_rc);
        }
    }
    return rc;
}
