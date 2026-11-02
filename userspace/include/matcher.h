#ifndef KALATRACE_RULES_H
#define KALATRACE_RULES_H

#include "event.h"

enum kalatrace_match_result {
    KALATRACE_MATCH_ERROR = -1,
    KALATRACE_MATCH_NO_MATCH = 0,
    KALATRACE_MATCH_ALERT = 1,
};

enum kalatrace_match_result kalatrace_match_exec_shell_by_server(struct kalatrace_event *event);

#endif
