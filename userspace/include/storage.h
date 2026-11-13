#ifndef KALATRACE_STORAGE_H
#define KALATRACE_STORAGE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

struct kalatrace_storage {
    sqlite3 *db;
};

int storage_init(struct kalatrace_storage *storage, const char *db_path);
int storage_close(struct kalatrace_storage *storage);


#endif
