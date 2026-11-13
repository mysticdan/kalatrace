#include "storage.h"

int test_null_storage(struct kalatrace_storage *storage)
{   
    int rc = storage_close(storage);
    if (rc == SQLITE_MISUSE) {
        printf("\033[1;32mtest_null_storage: Passed\033[0m\n");
        return 0;
    } 
    
    printf("\033[1;31mtest_null_storage: Failed (expected SQLITE_MISUSE, got %d)\033[0m\n", rc);
    return rc;
}

int test_valid_connection(struct kalatrace_storage *storage) 
{
    int rc = storage_close(storage);
    if (rc == SQLITE_OK) {
        printf("\033[1;32mtest_valid_connection: Passed\033[0m\n");
        return 0;
    } 
    
    printf("\033[1;31mtest_valid_connection: Failed (expected SQLITE_OK, got %d)\033[0m\n", rc);
    return rc;
} 

int test_double_close(struct kalatrace_storage *storage) 
{
    int rc = storage_close(storage);
    if (rc == SQLITE_MISUSE) {
        printf("\033[1;32mtest_double_close: passed\033[0m\n");
        return 0;
    }

    printf("\033[1;31mtest_double_close: Failed (expected SQLITE_MISUSE, got %d)\033[0m\n", rc);
    return rc;
}

int test_busy_connection_close(struct kalatrace_storage *storage) 
{
    sqlite3_stmt *stmt;
    const char *sql = "SELECT 1;";

    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("test_busy_connection_close: Failed to prepare statement (rc=%d)\n", rc);
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        printf("test_busy_connection_close: Failed to step statement (rc=%d)\n", rc);
        sqlite3_finalize(stmt);
        return rc;
    }

    // Now the database is busy with an open statement
    rc = storage_close(storage);
    if (rc == SQLITE_BUSY) {
        printf("\033[1;32mtest_busy_connection_close: Passed\033[0m\n");
        sqlite3_finalize(stmt);

        rc = storage_close(storage);
        if (rc != SQLITE_OK) {
            printf("test_busy_connection_close: Failed to close after finalizing statement (rc=%d)\n", rc);
            return rc;
        }
        printf("\033[1;32mtest_busy_connection_close: Successfully closed after finalizing statement\033[0m\n");
        return 0;
    }
    
    printf("\033[1;31mtest_busy_connection_close: Failed (expected SQLITE_BUSY, got %d)\033[0m\n", rc);
    sqlite3_finalize(stmt);
    return rc;
}

int main() 
{
    // Test 1: Close a NULL storage pointer
    struct kalatrace_storage *storage = NULL;
    if (test_null_storage(storage) != 0) {
        return 1;
    }
    storage = malloc(sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        return 1;
    }
    storage->db = NULL;
    if (test_null_storage(storage) != 0) {
        free(storage);
        storage = NULL;
        return 1;
    }

    // Test 2: Close a valid storage connection
    int rc = storage_init(storage, "/tmp/test_close_storage.db");
    if (rc != SQLITE_OK) {
        printf("test_valid_connection: Failed to initialize storage (rc=%d)\n", rc);
        free(storage);
        storage = NULL;
        return rc;
    }
    if (test_valid_connection(storage) != 0) {
        free(storage);
        storage = NULL;
        return 1;
    }

    // Test 3: Close a close storage connection
    if (test_double_close(storage) != 0) {
        free(storage);
        storage = NULL;
        return 1;
    }

    // Test 4: Close a busy storage connection
    rc = storage_init(storage, "/tmp/test_close_storage.db");
    if (rc != SQLITE_OK) {
        printf("test_busy_connection_close: Failed to initialize storage (rc=%d)\n", rc);
        free(storage);
        storage = NULL;
        return rc;
    }
    if (test_busy_connection_close(storage) != 0) {
        free(storage);
        storage = NULL;
        return 1;
    }

    free(storage);
    storage = NULL;

    return 0;
}
