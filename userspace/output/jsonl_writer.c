#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include "jsonl.h"

/* Escape JSON strings without converting 64-bit timestamps to floating point. */
static void write_json_string(FILE *fp, const char *str)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)str;

    fputc('"', fp);
    for (; *p != '\0'; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", fp);
            break;
        case '\\':
            fputs("\\\\", fp);
            break;
        case '\b':
            fputs("\\b", fp);
            break;
        case '\f':
            fputs("\\f", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*p < 0x20) {
                char escaped[] = "\\u0000";
                escaped[4] = hex[*p >> 4];
                escaped[5] = hex[*p & 0x0f];
                fputs(escaped, fp);
            } else {
                fputc(*p, fp);
            }
        }
    }
    fputc('"', fp);
}

int kalatrace_write_alert_jsonl(
    const char *path,
    const struct kalatrace_alert *alert
)
{
    FILE *fp;
    int saved_errno = 0;

    if (!path || !alert)
        return -1;

    fp = fopen(path, "a");
    if (!fp) {
        perror("failed to open alert file");
        return -1;
    }

    fprintf(fp, "{\"timestamp_ns\":%" PRIu64 ",\"rule_id\":", alert->timestamp_ns);
    write_json_string(fp, alert->rule_id);
    fputs(",\"severity\":", fp);
    write_json_string(fp, alert->severity);
    fputs(",\"message\":", fp);
    write_json_string(fp, alert->message);
    fprintf(fp,
        ",\"event_type\":%" PRIu32
        ",\"pid\":%" PRIu32
        ",\"ppid\":%" PRIu32
        ",\"uid\":%" PRIu32
        ",\"gid\":%" PRIu32,
        alert->event_type, alert->pid, alert->ppid, alert->uid, alert->gid);
    fputs(",\"comm\":", fp);
    write_json_string(fp, alert->comm);
    fputs(",\"parent_comm\":", fp);
    write_json_string(fp, alert->parent_comm);
    fputs(",\"exe_path\":", fp);
    write_json_string(fp, alert->exe_path);
    fputs(",\"path\":", fp);
    write_json_string(fp, alert->path);
    fputs("}\n", fp);

    if (ferror(fp))
        saved_errno = errno ? errno : EIO;

    /* Buffered writes can fail only when fclose flushes the stream. */
    if (fclose(fp) == EOF && !saved_errno)
        saved_errno = errno ? errno : EIO;

    if (saved_errno) {
        errno = saved_errno;
        perror("failed to write alert");
        return -1;
    }

    return 0;
}
