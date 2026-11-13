#include "storage.h"

void test_null_storage(struct kalatrace_storage *storage)
{   
    int rc = storage_close(storage);
    if (rc == SQLITE_MISUSE) {
        printf("test_null_storage: Passed\n");
    } else {
        printf("test_null_storage: Failed (expected SQLITE_MISUSE, got %d)\n", rc);
    }
}

void test_valid_connection(struct kalatrace_storage *storage) 
{
    int rc = storage_close(storage);
    if (rc == SQLITE_OK) {
        printf("test_valid_connection: Passed\n");
    } else {
        printf("test_valid_connection: Failed (expected SQLITE_OK, got %d)\n", rc);
    }
} 

void test_double_close(struct kalatrace_storage *storage) 
{
    int rc = storage_close(storage);
    if (rc == SQLITE_MISUSE) {
        printf("test_double_close: passed\n");
    }
}

void test_busy_connection_close(struct kalatrace_storage *storage) 
{
    sqlite3_stmt *stmt;
    const char *sql = "SELECT 1;";

    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("test_busy_connection_close: Failed to prepare statement (rc=%d)\n", rc);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        printf("test_busy_connection_close: Failed to step statement (rc=%d)\n", rc);
        sqlite3_finalize(stmt);
        return;
    }

    // Now the database is busy with an open statement
    rc = storage_close(storage);
    if (rc == SQLITE_BUSY) {
        printf("test_busy_connection_close: Passed\n");
        sqlite3_finalize(stmt);
    } else {
        printf("test_busy_connection_close: Failed (expected SQLITE_BUSY, got %d)\n", rc);
        sqlite3_finalize(stmt);
    }
}

int main() 
{
    // Test 1: Close a NULL storage pointer
    struct kalatrace_storage *storage = malloc(sizeof(struct kalatrace_storage));
    storage->db = NULL;
    test_null_storage(storage);

    // Test 2: Close a valid storage connection
    int rc = storage_init(storage, "/tmp/test_close_storage.db");
    if (rc != SQLITE_OK) {
        printf("test_valid_connection: Failed to initialize storage (rc=%d)\n", rc);
        return 1;
    }
    test_valid_connection(storage);

    // Test 3: Close a close storage connection
    test_double_close(storage);

    // Test 4: Close a busy storage connection
    rc = storage_init(storage, "/tmp/test_close_storage.db");
    if (rc != SQLITE_OK) {
        printf("test_busy_connection_close: Failed to initialize storage (rc=%d)\n", rc);
        return 1;
    }
    test_busy_connection_close(storage);

    storage_close(storage);
}