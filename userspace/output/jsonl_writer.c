#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "jsonl.h"

int kalatrace_write_alert_jsonl(
	const char *path,
	const struct kalatrace_alert *alert
)
{
	FILE *fp;

	if (!path || !alert)
		return -1;

	fp = fopen(path, "a");
	if (!fp) {
		perror("failed to open file");
		return -1;
	}

	fprintf(fp,
		"{"
		"\"timestamp_ns\":%lu,"
		"\"rule_id\":\"%s\","
		"\"severity\":\"%s\","
		"\"message\":\"%s\","
		"\"event_type\":%u,"
		"\"pid\":%u,"
		"\"ppid\":%u,"
		"\"uid\":%u,"
		"\"gid\":%u,"
		"\"comm\":\"%s\","
		"\"parent_comm\":\"%s\","
		"\"exe_path\":\"%s\","
		"\"path\":\"%s\""
		"}\n",
		alert->timestamp_ns,
		alert->rule_id,
		alert->severity,
		alert->message,
		alert->event_type,
		alert->pid,
		alert->ppid,
		alert->uid,
		alert->gid,
		alert->comm,
		alert->parent_comm,
		alert->exe_path,
		alert->path
	);

	fclose(fp);
	return 0;
}
