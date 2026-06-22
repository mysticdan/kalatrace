#ifndef KALATRACE_JSONL_H
#define KALATRACE_JSONL_H

#include "alert.h"

int kalatrace_write_alert_jsonl(
	const char *path,
	const struct kalatrace_alert *alert
);

#endif