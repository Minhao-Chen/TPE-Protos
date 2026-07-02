#include <stdio.h>
#include <time.h>

#include "access_log.h"
#include "netutils.h"

static FILE *log_file = NULL;

void
access_log_init(FILE *out){
    log_file = (out != NULL) ? out : stderr;
}

void
access_log_record(const char *username, const struct sockaddr *client, uint8_t atyp, const char *dest_addr, uint16_t dest_port, uint8_t rep_status){
    if (log_file == NULL) {
        return; /* no se inicializó el log */
    }

    /* timestamp en formato ISO 8601 UTC */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char timestamp[21]; /* YYYY-MM-DDTHH:MM:SSZ + null terminator */
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    char client_str[SOCKADDR_TO_HUMAN_MIN];
    sockaddr_to_human(client_str, sizeof(client_str), client);

    const char *user = (username != NULL) ? username : "-";

    const char *dst = (dest_addr != NULL) ? dest_addr : "-";

    fprintf(log_file, "%s\t%s\t%s\t%s:%u\t0x%02X\n",
            timestamp,
            user,
            client_str,
            dst,
            dest_port,
            rep_status);

    fflush(log_file);
}