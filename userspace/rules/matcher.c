#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>	

#include "matcher.h"

static int str_in_list(const char *value, const char *const list[])
{
	for (int i = 0; list[i] != NULL; i++) {
		if (strcmp(value, list[i]) == 0)
			return 1;
	}

	return 0;
}

enum kalatrace_match_result kalatrace_match_exec_shell_by_server(struct kalatrace_event *event)
{
	const char *const shells[] = {
		"sh", "bash", "dash", "zsh", NULL
	};

	const char *const server_processes[] = {
		"nginx", "apache2", "httpd", "php-fpm", "gunicorn", NULL
	};

	if (!event)
		return KALATRACE_MATCH_ERROR;

	if (event->type != KALATRACE_EVENT_EXEC)
		return KALATRACE_MATCH_NO_MATCH;

	if (!str_in_list(event->comm, shells))
		return KALATRACE_MATCH_NO_MATCH;

	if (!str_in_list(event->parent_comm, server_processes))
		return KALATRACE_MATCH_NO_MATCH;

	return KALATRACE_MATCH_ALERT;
}
