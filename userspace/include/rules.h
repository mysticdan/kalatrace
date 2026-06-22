#ifndef KALATRACE_RULES_H
#define KALATRACE_RULES_H

#include "event.h"
#include "alert.h"

int kalatrace_match_exec_shell_by_server(
	const char *json_path,
	struct kalatrace_event *event,
	struct kalatrace_alert *alert
);

#endif