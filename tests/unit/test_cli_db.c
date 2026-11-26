#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "storage.h"

static int test_binary(char const *const path, char *const argv[], int expected_exit)
{
    int status;
    pid_t pid;
    pid_t ret;

    pid = fork();

    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        execv(path, argv);
        perror("execv");
        _exit(127);
    }

    do {
        ret = waitpid(pid, &status, 0);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "[FAIL] Terminated by signal: %d\n", WTERMSIG(status));
        return -1;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "[FAIL] Abnormal termination\n");
        return -1;
    }

    int actual_exit = WEXITSTATUS(status);

    if (actual_exit != expected_exit) {
        fprintf(stderr, "[FAIL] Expected: %d, actual: %d\n", expected_exit, actual_exit);
        return -1;
    }

    printf("[PASS] Exit code: %d\n", actual_exit);

    return 0;
}

static int check_match_event(char const *const binary, char *const argv[])
{
    int expected_exit = 0;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_match_event: Failed\033[0m\n");
        return 1;
    }

    printf("\033[1;32mcheck_match_event: Passed\033[0m\n");
    return 0;
}

static int check_no_match_event(char const *const binary, char *const argv[])
{
    int expected_exit = 1;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_no_match_event: Failed\033[0m\n");
        return 1;
    }

    printf("\033[1;32mcheck_no_match_event: Passed\033[0m\n");
    return 0;
}

static int check_second_time_match_event(char const *const binary, char *const argv[])
{
    int expected_exit = 0;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_second_time_match_event: Failed\033[0m\n");
        return -1;
    }

    struct kalatrace_storage *storage = calloc(1, sizeof(struct kalatrace_storage));
    if (storage == NULL) {
        fprintf(stderr, "Failed to allocate memory for storage\n");
        return -1;
    }

    int rc = storage_init(storage, argv[3]);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize storage with database: /tmp/test-event-db\n");
        free(storage);
        return rc;
    }

    uint64_t count_alerts = 0;
    rc = storage_count_alerts(storage, &count_alerts);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to count alerts in database: %s\n", argv[3]);
        int close_rc = storage_close(storage);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage\n");
        }
        free(storage);
        return rc;
    }

    if (count_alerts != 2) {
        printf("\033[1;31mcheck_second_time_match_event: Failed - Expected 2 alerts, found %" PRIu64 "\033[0m\n", count_alerts);
        int close_rc = storage_close(storage);
        if (close_rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close storage\n");
        }
        free(storage);
        return 1;
    }

    rc = storage_close(storage);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to close storage\n");
        free(storage);
        return rc;
    }
    free(storage);
    printf("\033[1;32mcheck_second_time_match_event: Passed\033[0m\n");
    return 0;
}

static int check_invalid_json(char const *const binary, char *const argv[])
{
    int expected_exit = 255;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_invalid_json: Failed\033[0m\n");
        return -1;
    }

    printf("\033[1;32mcheck_invalid_json: Passed\033[0m\n");
    return 0;
}

static int check_timestamp_int64_exceeded(char const *const binary, char *const argv[])
{
    int expected_exit = SQLITE_TOOBIG;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_timestamp_int64_exceeded: Failed\033[0m\n");
        return 1;
    }

    printf("\033[1;32mcheck_timestamp_int64_exceeded: Passed\033[0m\n");
    return 0;
}

static int check_wrong_arguments(char const *const binary, char *const argv[])
{
    int expected_exit = 255;
    if (test_binary(binary, argv, expected_exit) != 0) {
        printf("\033[1;31mcheck_wrong_arguments: Failed\033[0m\n");
        return 1;
    }

    printf("\033[1;32mcheck_wrong_arguments: Passed\033[0m\n");
    return 0;
}

int main()
{
    char path[] = "/tmp/test-event-db-XXXXXX";
    int fd = mkstemp(path);
    if (fd == -1) {
        perror("mkstemp");
        return 1;
    }
    if (close(fd) != 0) {
        perror("close");
        unlink(path);
        return 1;
    }

    char const *const binary_path = "../../build/tests/kalatracectl";
    char *const match_event[] = { "kalatracectl", "test-event-db", "../fixtures/exec_nginx_shell.json", path, NULL };
    char *const no_match_event[] = { "kalatracectl", "test-event-db", "../fixtures/no_match_event.json", path, NULL };
    char *const invalid_json[] = { "kalatracectl", "test-event-db", "../fixtures/invalid_json_event.json", path, NULL };
    char *const timestamp_int64_exceeded[] = { "kalatracectl", "test-event-db", "../fixtures/timestamp_exceeded_event.json", path, NULL };
    char *const wrong_arguments[] = { "kalatracectl", "test-event-db", "../fixtures/exec_nginx_shell.json", NULL };

    if(check_match_event(binary_path, match_event) != 0) {
        return 1;
    }

    if(check_no_match_event(binary_path, no_match_event) != 0) {
        return 1;
    }

    if(check_second_time_match_event(binary_path, match_event) != 0) {
        return 1;
    }

    if(check_invalid_json(binary_path, invalid_json) != 0) {
        return 1;
    }

    if(check_timestamp_int64_exceeded(binary_path, timestamp_int64_exceeded) != 0) {
        return 1;
    }

    if(check_wrong_arguments(binary_path, wrong_arguments) != 0) {
        return 1;
    }

    unlink(path);

    return 0;
}
