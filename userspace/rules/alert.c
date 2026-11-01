#include "alert.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int kalatrace_create_alert_from_event(struct kalatrace_event *event, struct kalatrace_alert *alert)
{
    if (!event || !alert)
        return -1;

    memset(alert, 0, sizeof(*alert));
    
    alert->timestamp_ns = event->timestamp_ns;
    snprintf(alert->rule_id, sizeof(alert->rule_id), "EXEC_SHELL_BY_SERVER_PROCESS");
    snprintf(alert->severity, sizeof(alert->severity), "high");
    snprintf(alert->message, sizeof(alert->message), "Shell process spawned by server process");
    alert->event_type = event->type;
    alert->pid = event->pid;
    alert->ppid = event->ppid;
    alert->uid = event->uid;
    alert->gid = event->gid;
    snprintf(alert->comm, sizeof(alert->comm), "%s", event->comm);
    snprintf(alert->parent_comm, sizeof(alert->parent_comm), "%s", event->parent_comm);
    snprintf(alert->path, sizeof(alert->path), "%s", event->path);
    snprintf(alert->exe_path, sizeof(alert->exe_path), "%s", event->exe_path);
    
    return 0;
}
