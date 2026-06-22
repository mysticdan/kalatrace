#include <stdio.h>
#include <string.h>
#include "event.h"
#include "alert.h"
#include "rules.h"
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
        
        if (kalatrace_match_exec_shell_by_server(json_path, &event, &alert) != 0) {
            fprintf(stderr, "Failed to evaluate rules for event: %s\n", json_path);
            return -1;
        }

        if (kalatrace_write_alert_jsonl("alerts.jsonl", &alert) != 0) {
            fprintf(stderr, "Failed to write alert to JSONL file\n");
            return -1;
        }

        printf("Alert generated and written to alerts.jsonl\n");

    }

    return 0;
}