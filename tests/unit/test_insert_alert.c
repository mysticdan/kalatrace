#include "storage.h"
#include <time.h>
#include <unistd.h>

static int insert_one_alert(struct kalatrace_storage *storage) 
{
    struct kalatrace_alert alert = {
        .timestamp_ns = (uint64_t)time(NULL) * 1000000000,
        .rule_id = "rule1",
        .severity = "high",
        .message = "Test alert",
        .event_type = 1,
        .pid = 1234,
        .ppid = 5678,
        .uid = 1000,
        .gid = 1000,
        .comm = "test_comm",
        .parent_comm = "test_parent_comm",
        .path = "/path/to/file",
        .exe_path = "/path/to/exe"
    };

    struct kalatrace_alert *alerts[1] = { &alert };
    int rc = storage_insert_alert(storage, alerts, 1);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to insert alert: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    uint64_t count = 0;
    rc = storage_count_alerts(storage, &count);
    if (rc != SQLITE_OK || count != 1) {
        printf("\033[1;31minsert_one_alert: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }

    sqlite3_stmt *stmt;
    const char *sql = "SELECT timestamp_ns, rule_id, severity, message, event_type, pid, ppid, uid, gid, comm, parent_comm, path, exe_path FROM alerts WHERE id = 1;";
    rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement for alert retrieval: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(storage->db));
        sqlite3_finalize(stmt);
        return rc;
    }

    // Check the retrieved values
    uint64_t retrieved_timestamp = (uint64_t)sqlite3_column_int64(stmt, 0);
    const char *retrieved_rule_id = (const char *)sqlite3_column_text(stmt, 1);
    const char *retrieved_severity = (const char *)sqlite3_column_text(stmt, 2);
    const char *retrieved_message = (const char *)sqlite3_column_text(stmt, 3);
    uint32_t retrieved_event_type = (uint32_t)sqlite3_column_int(stmt, 4);
    uint32_t retrieved_pid = (uint32_t)sqlite3_column_int(stmt, 5);
    uint32_t retrieved_ppid = (uint32_t)sqlite3_column_int(stmt, 6);
    uint32_t retrieved_uid = (uint32_t)sqlite3_column_int(stmt, 7);
    uint32_t retrieved_gid = (uint32_t)sqlite3_column_int(stmt, 8);
    const char *retrieved_comm = (const char *)sqlite3_column_text(stmt, 9);
    const char *retrieved_parent_comm = (const char *)sqlite3_column_text(stmt, 10);
    const char *retrieved_path = (const char *)sqlite3_column_text(stmt, 11);
    const char *retrieved_exe_path = (const char *)sqlite3_column_text(stmt, 12);

    if (retrieved_timestamp != alert.timestamp_ns ||
        strcmp(retrieved_rule_id, alert.rule_id) != 0 ||
        strcmp(retrieved_severity, alert.severity) != 0 ||
        strcmp(retrieved_message, alert.message) != 0 ||
        retrieved_event_type != alert.event_type ||
        retrieved_pid != alert.pid ||
        retrieved_ppid != alert.ppid ||
        retrieved_uid != alert.uid ||
        retrieved_gid != alert.gid ||
        strcmp(retrieved_comm, alert.comm) != 0 ||
        strcmp(retrieved_parent_comm, alert.parent_comm) != 0 ||
        strcmp(retrieved_path, alert.path) != 0 ||
        strcmp(retrieved_exe_path, alert.exe_path) != 0) 
    {
        printf("\033[1;31minsert_one_alert: Failed (retrieved values do not match)\033[0m\n");
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to finalize statement after mismatch: %s\n", sqlite3_errmsg(storage->db));
        }
        return 1;
    }

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to finalize statement after successful retrieval: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    printf("\033[1;32minsert_one_alert: Passed\033[0m\n");
    return 0;
}

static int insert_many_alerts(struct kalatrace_storage *storage) 
{
    const int num_alerts = 5;
    struct kalatrace_alert alerts[num_alerts];

    for (int i = 0; i < num_alerts; i++) {
        struct kalatrace_alert alert = {
            .timestamp_ns = (uint64_t)time(NULL) * 1000000000 + i,
            .rule_id = "rule1",
            .severity = "high",
            .message = "Test alert \" ' \\",
            .event_type = 1,
            .pid = 1234 + i,
            .ppid = 5678 + i,
            .uid = 1000 + i,
            .gid = 1000 + i,
            .comm = "test_comm",
            .parent_comm = "test_parent_comm",
            .path = "/path/to/file",
            .exe_path = "/path/to/exe"
        };
        alerts[i] = alert;
    }

    struct kalatrace_alert *alert_ptrs[num_alerts];
    for (int i = 0; i < num_alerts; i++) {
        alert_ptrs[i] = &alerts[i];
    }

    int rc = storage_insert_alert(storage, alert_ptrs, num_alerts);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to insert many alerts: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    uint64_t count = 0;
    rc = storage_count_alerts(storage, &count);
    if (rc != SQLITE_OK || count != num_alerts + 1) {
        printf("\033[1;31minsert_many_alerts: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }

    sqlite3_stmt *stmt;
    const char *sql = "SELECT timestamp_ns, rule_id, severity, message, event_type, pid, ppid, uid, gid, comm, parent_comm, path, exe_path FROM alerts WHERE id > 1 ORDER BY id ASC;";
    rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(storage->db));
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(storage->db));
        sqlite3_finalize(stmt);
        return rc;
    }

    for (int i = 0; i < num_alerts; i++) {
        uint64_t retrieved_timestamp = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *retrieved_rule_id = (const char *)sqlite3_column_text(stmt, 1);
        const char *retrieved_severity = (const char *)sqlite3_column_text(stmt, 2);
        const char *retrieved_message = (const char *)sqlite3_column_text(stmt, 3);
        uint32_t retrieved_event_type = (uint32_t)sqlite3_column_int(stmt, 4);
        uint32_t retrieved_pid = (uint32_t)sqlite3_column_int(stmt, 5);
        uint32_t retrieved_ppid = (uint32_t)sqlite3_column_int(stmt, 6);
        uint32_t retrieved_uid = (uint32_t)sqlite3_column_int(stmt, 7);
        uint32_t retrieved_gid = (uint32_t)sqlite3_column_int(stmt, 8);
        const char *retrieved_comm = (const char *)sqlite3_column_text(stmt, 9);
        const char *retrieved_parent_comm = (const char *)sqlite3_column_text(stmt, 10);
        const char *retrieved_path = (const char *)sqlite3_column_text(stmt, 11);
        const char *retrieved_exe_path = (const char *)sqlite3_column_text(stmt, 12);

        if (retrieved_timestamp != alerts[i].timestamp_ns ||
            strcmp(retrieved_rule_id, alerts[i].rule_id) != 0 ||
            strcmp(retrieved_severity, alerts[i].severity) != 0 ||
            strcmp(retrieved_message, alerts[i].message) != 0 ||
            retrieved_event_type != alerts[i].event_type ||
            retrieved_pid != alerts[i].pid ||
            retrieved_ppid != alerts[i].ppid ||
            retrieved_uid != alerts[i].uid ||
            retrieved_gid != alerts[i].gid ||
            strcmp(retrieved_comm, alerts[i].comm) != 0 ||
            strcmp(retrieved_parent_comm, alerts[i].parent_comm) != 0 ||
            strcmp(retrieved_path, alerts[i].path) != 0 ||
            strcmp(retrieved_exe_path, alerts[i].exe_path) != 0) 
        {
            printf("\033[1;31minsert_many_alerts: Failed (retrieved values do not match for alert %d (rc=%d))\033[0m\n", i + 1, rc);
            printf("Expected: timestamp=%" PRIu64 ", rule_id=%s, severity=%s, message=%s, event_type=%u, pid=%u, ppid=%u, uid=%u, gid=%u, comm=%s, parent_comm=%s, path=%s, exe_path=%s\n",
                alerts[i].timestamp_ns, alerts[i].rule_id, alerts[i].severity, alerts[i].message,
                alerts[i].event_type, alerts[i].pid, alerts[i].ppid, alerts[i].uid, alerts[i].gid,
                alerts[i].comm, alerts[i].parent_comm, alerts[i].path, alerts[i].exe_path);
            printf("Retrieved: timestamp=%" PRIu64 ", rule_id=%s, severity=%s, message=%s, event_type=%u, pid=%u, ppid=%u, uid=%u, gid=%u, comm=%s, parent_comm=%s, path=%s, exe_path=%s\n",
                retrieved_timestamp, retrieved_rule_id, retrieved_severity, retrieved_message,
                retrieved_event_type, retrieved_pid, retrieved_ppid, retrieved_uid, retrieved_gid,
                retrieved_comm, retrieved_parent_comm, retrieved_path, retrieved_exe_path);
            printf("%d\n", i);
            rc = sqlite3_finalize(stmt);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to finalize statement after mismatch: %s (rc=%d)\n", sqlite3_errmsg(storage->db), rc);
            }
            return 1;
        }

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            fprintf(stderr, "Failed to step to next row: %s (rc=%d)\n", sqlite3_errmsg(storage->db), rc);
            sqlite3_finalize(stmt);
            return 1;
        }

    }

    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to finalize statement: %s (rc=%d)\n", sqlite3_errmsg(storage->db), rc);
        return rc;
    }

    printf("\033[1;32minsert_many_alerts: Passed\033[0m\n");

    return 0;
}

static int timestamp_exceeds_int64_max(struct kalatrace_storage *storage) 
{
    struct kalatrace_alert alert = {
        .timestamp_ns = (uint64_t)INT64_MAX + 1,
        .rule_id = "rule1",
        .severity = "high",
        .message = "Test alert",
        .event_type = 1,
        .pid = 1234,
        .ppid = 5678,
        .uid = 1000,
        .gid = 1000,
        .comm = "test_comm",
        .parent_comm = "test_parent_comm",
        .path = "/path/to/file",
        .exe_path = "/path/to/exe"
    };

    struct kalatrace_alert *alerts[1] = { &alert };
    int rc = storage_insert_alert(storage, alerts, 1);
    if (rc != SQLITE_TOOBIG) {
        printf("\033[1;31mtimestamp_exceeds_int64_max: Failed (rc=%d)\033[0m\n", rc);
        return 1;
    }

    printf("\033[1;32mtimestamp_exceeds_int64_max: Passed (rc=%d)\033[0m\n", rc);
    return 0;
}

static int check_second_failed_alert(struct kalatrace_storage *storage) 
{
    struct kalatrace_alert alert1 = {
        .timestamp_ns = (uint64_t)time(NULL) * 1000000000,
        .rule_id = "rule1",
        .severity = "high",
        .message = "Test alert 1",
        .event_type = 1,
        .pid = 1234,
        .ppid = 5678,
        .uid = 1000,
        .gid = 1000,
        .comm = "test_comm_1",
        .parent_comm = "parent_comm_1",
        .path = "/path/to/file1",
        .exe_path = "/path/to/exe1"
    };

    struct kalatrace_alert alert2 = {
        .timestamp_ns = (uint64_t)INT64_MAX + 1,
        .rule_id = "rule2",
        .severity = "medium",
        .message = "Test alert 2",
        .event_type = 2,
        .pid = 2345,
        .ppid = 6789,
        .uid = 1001,
        .gid = 1001,
        .comm = "test_comm_2",
        .parent_comm = "parent_comm_2",
        .path = "/path/to/file2",
        .exe_path = "/path/to/exe2"
    };

    struct kalatrace_alert *alerts[2] = { &alert1, &alert2 };
    int rc = storage_insert_alert(storage, alerts, 2);
    if (rc == SQLITE_OK) {
        printf("\033[1;31mcheck_second_failed_alert: Failed (rc=%d)\033[0m\n", rc);
        return 1;
    }
    
    printf("\033[1;32mcheck_second_failed_alert: Passed (rc=%d)\033[0m\n", rc);
    return 0;
}

static int check_null_alert_in_array(struct kalatrace_storage *storage) 
{
    struct kalatrace_alert alert1 = {
        .timestamp_ns = (uint64_t)time(NULL) * 1000000000,
        .rule_id = "rule1",
        .severity = "high",
        .message = "Test alert 1",
        .event_type = 1,
        .pid = 1234,
        .ppid = 5678,
        .uid = 1000,
        .gid = 1000,
        .comm = "test_comm_1",
        .parent_comm = "parent_comm_1",
        .path = "/path/to/file1",
        .exe_path = "/path/to/exe1"
    };

    struct kalatrace_alert *alerts[2] = { &alert1, NULL };
    int rc = storage_insert_alert(storage, alerts, 2);
    if (rc == SQLITE_OK) {
        printf("\033[1;31mcheck_null_alert_in_array: Failed (rc=%d)\033[0m\n", rc);
        return 1;
    }
    
    printf("\033[1;32mcheck_null_alert_in_array: Passed (rc=%d)\033[0m\n", rc);
    return 0;
}

static int check_invalid_arguments(struct kalatrace_storage *storage) 
{
    struct kalatrace_alert alert;
    struct kalatrace_alert *alerts[1] = { &alert };

    // Check closed storage
    int rc = storage_insert_alert(storage, alerts, 1);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (CLOSED storage, rc=%d)\033[0m\n", rc);
        return 1;
    }

    // Check Null storage
    rc = storage_insert_alert(NULL, alerts, 1);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL storage, rc=%d)\033[0m\n", rc);
        return 1;
    }

    // Check NULL alerts
    rc = storage_insert_alert(storage, NULL, 1);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL alerts, rc=%d)\033[0m\n", rc);
        return 1;
    }

    printf("\033[1;32mcheck_invalid_arguments: Passed\033[0m\n");
    return 0;
}

int main()
{
    // Create temporary database
    char path[] = "/tmp/test-insert-alerts-XXXXXX";
    int fd = mkstemp(path);
    if (fd == -1) {
        perror("mkstemp");
        return 1;
    }
    if (close(fd) != 0) {
        perror("close");
        unlink(path);
        return 1;
    }
    struct kalatrace_storage *storage = calloc(1, sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        unlink(path);
        return 1;
    }
    storage->db = NULL;

    // Initialize storage
    int rc = storage_init(storage, path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        unlink(path);
        return rc;
    }

    // Insert one alert and check if it was inserted correctly
    if (insert_one_alert(storage) != 0) {
        fprintf(stderr, "Failed to insert one alert\n");
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    // Insert many alerts and check if they were inserted correctly
    if (insert_many_alerts(storage) != 0) {
        fprintf(stderr, "Failed to insert many alerts\n");
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    // Check timestamp exceeds INT64_MAX
    if (timestamp_exceeds_int64_max(storage) != 0) {
        fprintf(stderr, "Failed to check timestamp exceeds INT64_MAX\n");
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    // Check null alert in array
    if (check_null_alert_in_array(storage) != 0) {
        fprintf(stderr, "Failed to check null alert in array\n");
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    // Check second failed alert
    if (check_second_failed_alert(storage) != 0) {
        fprintf(stderr, "Failed to check second failed alert\n");
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    // Check consistency before and after close storage
    uint64_t count_before_close = 0;
    rc = storage_count_alerts(storage, &count_before_close);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count alerts before close: %s\n", sqlite3_errstr(rc));
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }

    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        unlink(path);
        return rc;
    }

    rc = storage_init(storage, path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to re-initialize storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        unlink(path);
        return rc;
    }

    uint64_t count_after_close = 0;
    rc = storage_count_alerts(storage, &count_after_close);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count alerts after close: %s\n", sqlite3_errstr(rc));
        free(storage);
        unlink(path);
        return 1;
    }

    if (count_before_close != count_after_close) {
        printf("\033[1;31mcheck_consistency_before_after_close: Failed (before=%" PRIu64 ", after=%" PRIu64 ")\033[0m\n", count_before_close, count_after_close);
        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        }
        free(storage);
        unlink(path);
        return 1;
    }
    
    printf("\033[1;32mcheck_consistency_before_after_close: Passed (count=%" PRIu64 ")\033[0m\n", count_after_close);

    // check invalid arguments
    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        unlink(path);
        return rc;
    }
    if (check_invalid_arguments(storage) != 0) {
        fprintf(stderr, "Failed to check invalid arguments\n");
        free(storage);
        unlink(path);
        return 1;
    }
    
    // Clean up
    free(storage);
    unlink(path);
    return 0;
}
