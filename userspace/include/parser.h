#ifndef KALATRACE_PARSER_H
#define KALATRACE_PARSER_H

#include "event.h"

int kalatrace_parse_file_to_event(const char *path, struct kalatrace_event *event);

#endif