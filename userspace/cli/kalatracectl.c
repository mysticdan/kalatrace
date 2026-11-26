#include <stdio.h>
#include <string.h>
#include "event.h"
#include "alert.h"
#include "matcher.h"
#include "parser.h"
#include "jsonl.h"
#include "storage.h"

static void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s <command>\n", prog_name);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  test-event       Test event processing and alert generation\n");
    fprintf(stderr, "  test-event-db    Test event processing with a database\n");
}

static int command_check(const char *command)
{
    if (strcmp(command, "test-event") == 0) {
        return 1;
    } else if (strcmp(command, "test-event-db") == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int test_event(const char *json_path)
{
    struct kalatrace_event event;
    struct kalatrace_alert alert;

    int rc = kalatrace_parse_file_to_event(json_path, &event);
    if (rc != 0) {
        fprintf(stderr, "Failed to parse event from JSON file: %s\n", json_path);
        return rc;
    }

    enum kalatrace_match_result match_result = kalatrace_match_exec_shell_by_server(&event);

    if (match_result == KALATRACE_MATCH_ERROR) {
        fprintf(stderr, "Failed to evaluate rules for event: %s\n", json_path);
        return match_result;
    }

    if (match_result == KALATRACE_MATCH_NO_MATCH) {
        printf("Alert not match, no alert generated for event: %s\n", json_path);
        return match_result;
    }

    rc = kalatrace_create_alert_from_event(&event, &alert);
    if (rc != 0) {
        fprintf(stderr, "Failed to create alert from event: %s\n", json_path);
        return rc;
    }

    rc = kalatrace_write_alert_jsonl("alerts.jsonl", &alert);
    if (rc != 0) {
        fprintf(stderr, "Failed to write alert to JSONL file\n");
        return rc;
    }

    printf("Alert generated and written to alerts.jsonl\n");
    return KALATRACE_MATCH_ALERT;
}

static int test_event_db(const char *json_path, const char *db_path)
{
    struct kalatrace_event event;
    struct kalatrace_alert alert;

    int rc = kalatrace_parse_file_to_event(json_path, &event);
    if (rc != 0) {
        fprintf(stderr, "Failed to parse event from JSON file: %s\n", json_path);
        return rc;
    }

    enum kalatrace_match_result match_result = kalatrace_match_exec_shell_by_server(&event);

    if (match_result == KALATRACE_MATCH_ERROR) {
        fprintf(stderr, "Failed to evaluate rules for event: %s\n", json_path);
        return match_result;
    }

    if (match_result == KALATRACE_MATCH_NO_MATCH) {
        printf("Alert not match, no alert generated for event: %s\n", json_path);
        return match_result;
    }

    rc = kalatrace_create_alert_from_event(&event, &alert);
    if (rc != 0) {
        fprintf(stderr, "Failed to create alert from event: %s\n", json_path);
        return rc;
    }

    struct kalatrace_storage *storage = calloc(1, sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        return -1;
    }

    rc = storage_init(storage, db_path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize storage with database: %s\n", db_path);
        free(storage);
        return rc;
    }

    struct kalatrace_alert *alerts[1] = { &alert };

    rc = storage_insert_alert(storage, alerts, 1);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to write alert to database: %s\n", db_path);
        int close_rc = storage_close(storage);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage\n");
        }
        free(storage);
        return rc;
    }

    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage\n");
        free(storage);
        return rc;
    }
    free(storage);
    
    printf("Alert generated and written to database\n");
    
    return KALATRACE_MATCH_ALERT;
}

int main(int argc, char *argv[])
{
    if (argc < 2 || !command_check(argv[1])) {
        fprintf(stderr, "Unknown command");
        fflush(stderr);
		print_usage(argv[0]);
		return -1;
    }

    if (strcmp(argv[1], "test-event") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s test-event <json_input_path>\n", argv[0]);
            return -1;
        }
        return test_event(argv[2]);
    } else if (strcmp(argv[1], "test-event-db") == 0) {
        if (argc != 4) {
            fprintf(stderr, "usage: %s test-event-db <json_input_path> <db_path>\n", argv[0]);
            return -1;
        }
        return test_event_db(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        fflush(stderr);
        print_usage(argv[0]);
        return -1;
    }

}
