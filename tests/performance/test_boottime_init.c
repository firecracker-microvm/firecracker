/* This program is meant to be compiled statically, and run as the init process
 * in a Guest OS as part of a boottime timing. The boottime test will records
 * a timestamp before issuing the microvm power-on command, and this program
 * records another timestamp as the 1st user-space instruction, then writes it
 * to a log for the boottime test to retrieve.
 */

#include <sys/io.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define TIMESTAMP_LOG_FILE "/timestamp.log"
// Should match the one in `test_boottime.py`

#define TIMESTAMP_LOG_LINE "[%ld.%ld] init executed.\n"
// Will be parsed by the TIMESTAMP_LOG_REGEX regex in `test_boottime.py`

int main(int argc, char **argv) {
    struct timespec moment_realtime;
    clock_gettime(CLOCK_REALTIME, &moment_realtime);
    // Records this moment in time.

    FILE *timestamp_log;
    timestamp_log = fopen(TIMESTAMP_LOG_FILE, "w");
    fprintf(
        timestamp_log,
        TIMESTAMP_LOG_LINE,
        moment_realtime.tv_sec,
        moment_realtime.tv_nsec
    );
    fclose(timestamp_log);
    sync();
    // Saves timestamp to file, which can then be read by the host test.

    return 0;
    // Used in a Linux init process, this triggers system shutdown.
}
