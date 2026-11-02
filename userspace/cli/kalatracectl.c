#include <stdio.h>
#include <string.h>
#include "event.h"
#include "alert.h"
#include "matcher.h"
#include "parser.h"
#include "jsonl.h"

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <command> <json_input_path>\n", argv[0]);
		fprintf(stderr, "commands:\n");
		fprintf(stderr, "  test-event test.json\n");
		return -1;
    }

    if (strcmp(argv[1], "test-event") == 0) {

        const char *json_path = argv[2];
        
        struct kalatrace_event event;
        struct kalatrace_alert alert;

        if (kalatrace_parse_file_to_event(json_path, &event) != 0) {
            fprintf(stderr, "Failed to parse event from JSON file: %s\n", json_path);
            return -1;
        }

        enum kalatrace_match_result match_result = kalatrace_match_exec_shell_by_server(&event);

        if (match_result == KALATRACE_MATCH_ERROR) {
            fprintf(stderr, "Failed to evaluate rules for event: %s\n", json_path);
            return -1;
        }

        if (match_result == KALATRACE_MATCH_NO_MATCH) {
            printf("Alert not match, no alert generated for event: %s\n", json_path);
            return 0;
        }

        if (kalatrace_create_alert_from_event(&event, &alert) != 0) {
            fprintf(stderr, "Failed to create alert from event: %s\n", json_path);
            return -1;
        }

        if (kalatrace_write_alert_jsonl("alerts.jsonl", &alert) != 0) {
            fprintf(stderr, "Failed to write alert to JSONL file\n");
            return -1;
        }

        printf("Alert generated and written to alerts.jsonl\n");

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
