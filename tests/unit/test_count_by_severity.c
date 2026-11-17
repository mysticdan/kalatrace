#include "storage.h"
#include <time.h>
#include <inttypes.h>

static void create_alerts(struct kalatrace_storage *storage) {
    const char *sql = 
        "INSERT INTO alerts (timestamp_ns, rule_id, severity, message, event_type, pid, ppid, uid, gid, comm, parent_comm, path, exe_path) VALUES "
        "(strftime('%s','now') * 1000000000, 'rule1', 'high', 'Alert 1', 1, 1234, 5678, 1000, 1000, 'comm1', 'parent_comm1', '/path/to/file1', '/path/to/exe1'),"
        "(strftime('%s','now') * 1000000000, 'rule2', 'high', 'Alert 2', 2, 2345, 6789, 1001, 1001, 'comm2', 'parent_comm2', '/path/to/file2', '/path/to/exe2'),"
        "(strftime('%s','now') * 1000000000, 'rule3', 'high', 'Alert 3', 3, 3456, 7890, 1002, 1002, 'comm3', 'parent_comm3', '/path/to/file3', '/path/to/exe3'),"
        "(strftime('%s','now') * 1000000000, 'rule4', 'medium', 'Alert 4', 4, 4567, 8901, 1003, 1003, 'comm4', 'parent_comm4', '/path/to/file4', '/path/to/exe4'),"
        "(strftime('%s','now') * 1000000000, 'rule5', 'low', 'Alert 5', 5, 5678, 9012, 1004, 1004, 'comm5', 'parent_comm5', '/path/to/file5', '/path/to/exe5');";
    
    int rc = non_row_exec_sql(storage->db, sql);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to insert alerts: %s\n", sqlite3_errmsg(storage->db));
    }
}

static int check_empty_database(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts_by_severity(storage, "high", &count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count alerts: %s\n", sqlite3_errstr(rc));
        return rc;  
    }

    if(rc == SQLITE_OK && count == 0) {
        printf("\033[1;32mcheck_empty_database: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_empty_database: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }
}

static int check_count_by_severity(struct kalatrace_storage *storage) {
    uint64_t high_count = 0;
    uint64_t medium_count = 0;
    uint64_t low_count = 0;

    int rc = storage_count_alerts_by_severity(storage, "high", &high_count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count high severity alerts: %s\n", sqlite3_errstr(rc));
        return rc;
    }

    rc = storage_count_alerts_by_severity(storage, "medium", &medium_count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count medium severity alerts: %s\n", sqlite3_errstr(rc));
        return rc;
    }

    rc = storage_count_alerts_by_severity(storage, "low", &low_count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count low severity alerts: %s\n", sqlite3_errstr(rc));
        return rc;
    }

    if(rc == SQLITE_OK && high_count == 3 && medium_count == 1 && low_count == 1) {
        printf("\033[1;32mcheck_count_by_severity: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_count_by_severity: Failed (high=%" PRIu64 ", medium=%" PRIu64 ", low=%" PRIu64 ")\033[0m\n", high_count, medium_count, low_count);
        return 1;
    }
}

static int check_unknown_severity(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts_by_severity(storage, "unknown", &count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count unknown severity alerts: %s\n", sqlite3_errstr(rc));
        return rc;
    }

    if(rc == SQLITE_OK && count == 0) {
        printf("\033[1;32mcheck_unknown_severity: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_unknown_severity: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }
}

static int check_sensitivity_severity(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts_by_severity(storage, "HIGH", &count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count HIGH severity alerts: %s\n", sqlite3_errstr(rc));
        return rc;
    }

    if(rc == SQLITE_OK && count == 0) {
        printf("\033[1;32mcheck_sensitivity_severity: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_sensitivity_severity: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }
}

static int check_invalid_arguments(struct kalatrace_storage *storage) 
{
    uint64_t count = 0;

    // test after storage is closed
    int rc = storage_count_alerts_by_severity(storage, "high", &count);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (storage closed, rc=%d)\033[0m\n", rc);
        return 1;
    }

    rc = storage_count_alerts_by_severity(NULL, "high", &count);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL storage, rc=%d)\033[0m\n", rc);
        return 1;
    }

    rc = storage_count_alerts_by_severity(storage, NULL, &count);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL severity, rc=%d)\033[0m\n", rc);
        return 1;
    }

    rc = storage_count_alerts_by_severity(storage, "high", NULL);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL out_count, rc=%d)\033[0m\n", rc);
        return 1;
    }

    printf("\033[1;32mcheck_invalid_arguments: Passed\033[0m\n");
    return 0;
}

int main()
{   
    // Create temporary database
    char *path = malloc(128);
    if (path == NULL) {
        fprintf(stderr, "Failed to allocate memory for database path\n");
        return 1;
    }
    srand((unsigned int)time(NULL));
    snprintf(path, 128, "/tmp/test-count-alerts-by-severity-%08x.db", (unsigned int)rand());
    struct kalatrace_storage *storage = calloc(1, sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        return 1;
    }
    storage->db = NULL;

    // Initialize storage
    int rc = storage_init(storage, path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        free(path);
        return rc;
    }

    // Check empty database
    if (check_empty_database(storage) != 0) {
        free(storage);
        free(path);
        return 1;
    }

    // Create alerts (high=3, medium=1, low=1)
    create_alerts(storage);

    // Check count of alerts by severity
    if (check_count_by_severity(storage) != 0) {
        free(storage);
        free(path);
        return 1;
    }

    // Check unknown severity
    if (check_unknown_severity(storage) != 0) {
        free(storage);
        free(path);
        return 1;
    }

    // Check case sensitivity severity
    if (check_sensitivity_severity(storage) != 0) {
        free(storage);
        free(path);
        return 1;
    }

    // Close storage
    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        free(path);
        return rc;
    }

    // Check invalid arguments
    if (check_invalid_arguments(storage) != 0) {
        free(storage);
        free(path);
        return 1;
    }

    // Clean up
    free(storage);
    free(path);
    return 0;
}
