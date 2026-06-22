#ifndef KALATRACE_ALERT_H
#define KALATRACE_ALERT_H

#include <stdint.h>

#define KALATRACE_RULE_ID_LEN 64
#define KALATRACE_SEVERITY_LEN 16
#define KALATRACE_ALERT_MSG_LEN 256

struct kalatrace_alert {
	uint64_t timestamp_ns;

	char rule_id[KALATRACE_RULE_ID_LEN];
	char severity[KALATRACE_SEVERITY_LEN];
	char message[KALATRACE_ALERT_MSG_LEN];

	uint32_t event_type;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t gid;

	char comm[16];
	char parent_comm[16];
	char path[256];
	char exe_path[256];
};

#endif