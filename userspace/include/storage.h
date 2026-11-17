#ifndef KALATRACE_STORAGE_H
#define KALATRACE_STORAGE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <stdint.h>
#include <inttypes.h>
#include "alert.h"

struct kalatrace_storage {
    sqlite3 *db;
};

int storage_init(struct kalatrace_storage *storage, const char *db_path);
int storage_close(struct kalatrace_storage *storage);
int storage_count_alerts(struct kalatrace_storage *storage, uint64_t *out_count);
int storage_count_alerts_by_severity(struct kalatrace_storage *storage, const char *severity, uint64_t *out_count);
int storage_insert_alert(struct kalatrace_storage *storage, struct kalatrace_alert **alerts, const int count_alerts);
int non_row_exec_sql(sqlite3 *db, const char *sql);

#endif
