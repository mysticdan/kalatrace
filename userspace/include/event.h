#ifndef KALATRACE_EVENT_H
#define KALATRACE_EVENT_H

#include <stdint.h>

#define KALATRACE_COMM_LEN 16
#define KALATRACE_PATH_LEN 256

enum kalatrace_event_type {
	KALATRACE_EVENT_EXEC = 1,
	KALATRACE_EVENT_FILE_WRITE = 2,
	KALATRACE_EVENT_CHMOD = 3,
	KALATRACE_EVENT_NETWORK = 4,
};

enum kalatrace_severity {
	KALATRACE_SEV_INFO = 1,
	KALATRACE_SEV_LOW = 2,
	KALATRACE_SEV_MEDIUM = 3,
	KALATRACE_SEV_HIGH = 4,
	KALATRACE_SEV_CRITICAL = 5,
};

struct kalatrace_event {
	uint64_t timestamp_ns;

	uint32_t type;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t gid;

	char comm[KALATRACE_COMM_LEN];
	char parent_comm[KALATRACE_COMM_LEN];

	char path[KALATRACE_PATH_LEN];
	char exe_path[KALATRACE_PATH_LEN];

	uint32_t mode;
	uint32_t flags;
};

#endif