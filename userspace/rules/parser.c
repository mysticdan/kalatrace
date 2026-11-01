#include "parser.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

static bool json_get_u32(const cJSON *json, const char *key, uint32_t *out)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);

    if (!cJSON_IsNumber(item))
        return false;

    double n = item->valuedouble;

    if (!(n >= 0.0 && n <= UINT32_MAX))
        return false;

    uint32_t value = (uint32_t)n;

    if ((double)value != n)
        return false;

    *out = value;
    return true;
}

static const char *json_get_string(const cJSON *json, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);

    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static bool json_copy_string(const cJSON *json, const char *key, char *dst, size_t capacity)
{
    const char *src = json_get_string(json, key);

    if (!src)
        return false;

    size_t len = strlen(src);

    if (len >= capacity)
        return false;

    memcpy(dst, src, len + 1);
    return true;
}

static bool json_get_u64_string(const cJSON *json, const char *key, uint64_t *out)
{
    const char *src = json_get_string(json, key);

    if (!src || *src < '0' || *src > '9')
        return false;

    errno = 0;
    char *end;
    uintmax_t value = strtoumax(src, &end, 10);

    if (errno == ERANGE || *end != '\0' || value > UINT64_MAX)
        return false;

    *out = (uint64_t)value;
    return true;
}

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

static int parse_json_to_event(const cJSON *json, struct kalatrace_event *event)
{
    if (!cJSON_IsObject(json) || !event)
        return -1;

    struct kalatrace_event tmp = {0};

    const char *type = json_get_string(json, "event_type");

    if (!type)
        return -1;

    if (!json_get_u64_string(json, "timestamp_ns", &tmp.timestamp_ns) ||
        !json_get_u32(json, "type", &tmp.type) ||
        !json_get_u32(json, "pid", &tmp.pid) ||
        !json_get_u32(json, "ppid", &tmp.ppid) ||
        !json_get_u32(json, "uid", &tmp.uid) ||
        !json_get_u32(json, "gid", &tmp.gid) ||
        !json_get_u32(json, "mode", &tmp.mode) ||
        !json_get_u32(json, "flags", &tmp.flags) ||
        !json_copy_string(json, "comm", tmp.comm, sizeof(tmp.comm)) ||
        !json_copy_string(json, "parent_comm", tmp.parent_comm, sizeof(tmp.parent_comm)) ||
        !json_copy_string(json, "path", tmp.path, sizeof(tmp.path)) ||
        !json_copy_string(json, "exe_path", tmp.exe_path, sizeof(tmp.exe_path))) {
        return -1;
    }

    tmp.type = event_type_string_to_enum(type);

    if (tmp.type < 0) {
        return -1;
    }

    *event = tmp;
    return 0;
}

int kalatrace_parse_file_to_event(const char *path, struct kalatrace_event *event)
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

    if (parse_json_to_event(json, event) != 0) {
        fprintf(stderr, "failed to parse event from JSON in %s\n", path);
        cJSON_Delete(json);
        fclose(fp);
        return -1;
    }

	cJSON_Delete(json);
	fclose(fp);

	return 0;
}
