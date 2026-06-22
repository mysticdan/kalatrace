#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>	

#include "../include/event.h"
#include "../include/alert.h"
#include "../include/rules.h"

static int event_type_string_to_enum(const char *type_str)
{
	if (strcmp(type_str, "exec") == 0)
		return KALATRACE_EVENT_EXEC;
	if (strcmp(type_str, "file_write") == 0)
		return KALATRACE_EVENT_FILE_WRITE;
	if (strcmp(type_str, "chmod") == 0)
		return KALATRACE_EVENT_CHMOD;
	if (strcmp(type_str, "network") == 0)
		return KALATRACE_EVENT_NETWORK;

	return -1;
}


static int read_file_to_event(const char *path, struct kalatrace_event *event)
{
	FILE *fp;
	char buffer[1024];
	size_t read_size;

	if (!path || !event)
		return -1;

	fp = fopen(path, "r");
	if (!fp) {
		perror("failed to open file");
		return -1;
	}

	read_size = fread(buffer, 1, sizeof(buffer) - 1, fp);
	if (read_size <= 0) {
		fprintf(stderr, "failed to read from %s\n", path);
		fclose(fp);
		return -1;
	}
	buffer[read_size] = '\0';

	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
		fprintf(stderr, "failed to parse JSON from %s\n", path);
		fclose(fp);
		return -1;
	}

	event->timestamp_ns = cJSON_GetObjectItem(json, "timestamp_ns")->valuedouble;
	event->type = event_type_string_to_enum(cJSON_GetObjectItem(json, "event_type")->valuestring);
	event->pid = cJSON_GetObjectItem(json, "pid")->valueint;
	event->ppid = cJSON_GetObjectItem(json, "ppid")->valueint;
	event->uid = cJSON_GetObjectItem(json, "uid")->valueint;
	event->gid = cJSON_GetObjectItem(json, "gid")->valueint;
	snprintf(event->comm, sizeof(event->comm),
		 "%s", cJSON_GetObjectItem(json, "comm")->valuestring);
	snprintf(event->parent_comm, sizeof(event->parent_comm),
		 "%s", cJSON_GetObjectItem(json, "parent_comm")->valuestring);
	snprintf(event->path, sizeof(event->path),
		 "%s", cJSON_GetObjectItem(json, "path")->valuestring);
	snprintf(event->exe_path, sizeof(event->exe_path),
		 "%s", cJSON_GetObjectItem(json, "exe_path")->valuestring);
	event->mode = cJSON_GetObjectItem(json, "mode")->valueint;
	event->flags = cJSON_GetObjectItem(json, "flags")->valueint;

	cJSON_Delete(json);
	fclose(fp);

	return 0;
}

static int str_in_list(const char *value, const char *const list[])
{
	for (int i = 0; list[i] != NULL; i++) {
		if (strcmp(value, list[i]) == 0)
			return 1;
	}

	return 0;
}

int kalatrace_match_exec_shell_by_server(
	const char *json_path,
	struct kalatrace_event *event,
	struct kalatrace_alert *alert
)
{

	if (read_file_to_event(json_path, event) != 0) {
		fprintf(stderr, "Failed to read event from file: %s\n", json_path);
		return -1;
	}

	const char *const shells[] = {
		"sh", "bash", "dash", "zsh", NULL
	};

	const char *const server_processes[] = {
		"nginx", "apache2", "httpd", "php-fpm", "gunicorn", NULL
	};

	if (!event || !alert)
		return -1;

	if (event->type != KALATRACE_EVENT_EXEC)
		return -1;

	if (!str_in_list(event->comm, shells))
		return -1;

	if (!str_in_list(event->parent_comm, server_processes))
		return -1;

	memset(alert, 0, sizeof(*alert));

	alert->timestamp_ns = event->timestamp_ns;
	snprintf(alert->rule_id, sizeof(alert->rule_id),
		 "EXEC_SHELL_BY_SERVER_PROCESS");
	snprintf(alert->severity, sizeof(alert->severity), "high");
	snprintf(alert->message, sizeof(alert->message),
		 "Shell process spawned by server process");

	alert->event_type = event->type;
	alert->pid = event->pid;
	alert->ppid = event->ppid;
	alert->uid = event->uid;
	alert->gid = event->gid;

	snprintf(alert->comm, sizeof(alert->comm), "%s", event->comm);
	snprintf(alert->parent_comm, sizeof(alert->parent_comm), "%s",
		 event->parent_comm);
	snprintf(alert->path, sizeof(alert->path), "%s", event->path);
	snprintf(alert->exe_path, sizeof(alert->exe_path), "%s",
		 event->exe_path);

	return 0;
}