#include "storage.h"
#include <inttypes.h>
#include <time.h>

static void create_3_alerts(struct kalatrace_storage *storage) {
    const char *sql = 
        "INSERT INTO alerts (timestamp_ns, rule_id, severity, message, event_type, pid, ppid, uid, gid, comm, parent_comm, path, exe_path) VALUES "
        "(strftime('%s','now') * 1000000000, 'rule1', 'high', 'Alert 1', 1, 1234, 5678, 1000, 1000, 'comm1', 'parent_comm1', '/path/to/file1', '/path/to/exe1'),"
        "(strftime('%s','now') * 1000000000, 'rule2', 'medium', 'Alert 2', 2, 2345, 6789, 1001, 1001, 'comm2', 'parent_comm2', '/path/to/file2', '/path/to/exe2'),"
        "(strftime('%s','now') * 1000000000, 'rule3', 'low', 'Alert 3', 3, 3456, 7890, 1002, 1002, 'comm3', 'parent_comm3', '/path/to/file3', '/path/to/exe3');";
    
    int rc = non_row_exec_sql(storage->db, sql);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to insert alerts: %s\n", sqlite3_errmsg(storage->db));
    }
}

static int check_empty_database(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts(storage, &count);
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

static int check_3_alerts(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts(storage, &count);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count alerts: %s\n", sqlite3_errstr(rc));
        return rc;  
    }
    
    if(rc == SQLITE_OK && count == 3) {
        printf("\033[1;32mcheck_3_alerts: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_3_alerts: Failed (count=%" PRIu64 ")\033[0m\n", count);
        return 1;
    }
}

static int check_close_storage(struct kalatrace_storage *storage) {
    uint64_t count = 0;
    int rc = storage_count_alerts(storage, &count);
    if (rc == SQLITE_MISUSE) {
        printf("\033[1;32mcheck_close_storage: Passed\033[0m\n");
        return 0;
    } else {
        printf("\033[1;31mcheck_close_storage: Failed (rc=%d)\033[0m\n", rc);
        return 1;
    }   
}

static int check_invalid_arguments(struct kalatrace_storage *storage) 
{
    uint64_t count = 0;
    int rc = storage_count_alerts(NULL, &count);
    if (rc != SQLITE_MISUSE) {
        printf("\033[1;31mcheck_invalid_arguments: Failed (NULL storage, rc=%d)\033[0m\n", rc);
        return 1;
    }

    rc = storage_count_alerts(storage, NULL);
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
    snprintf(path, 128, "/tmp/test-count-alerts-%08x.db", (unsigned int)rand());

    // Storage initialization
    struct kalatrace_storage *storage = calloc(1, sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        return 1;
    }
    storage->db = NULL;
    int rc = storage_init(storage, path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        free(path);
        return rc;
    }
    // Check if the database is empty
    if (check_empty_database(storage) != 0) {
        return 1;
    }
    // Create 3 alerts
    create_3_alerts(storage);

    // Check if there are 3 alerts
    if (check_3_alerts(storage) != 0) {
        return 1;
    }

    // Check close storage
    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage: %s\n", sqlite3_errstr(rc));
        free(storage);
        free(path);
        return rc;
    }

    if (check_close_storage(storage) != 0) {
        return 1;
    }

    // Check invalid arguments
    if (check_invalid_arguments(storage) != 0) {
        return 1;
    }

    // Clean up
    free(storage);
    free(path);

    return 0;
}
