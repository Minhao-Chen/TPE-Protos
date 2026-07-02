/**
 * main.c - servidor proxy SOCKS5 (esqueleto base)
 *
 * Por ahora levanta un único socket pasivo TCP y atiende un servicio de "echo"
 * de ejemplo, multiplexando todas las conexiones en un solo hilo con el
 * selector no bloqueante de la cátedra.
 *
 * A medida que avancemos, `echo_passive_accept` se reemplazará por el accept de
 * SOCKS5, y se agregará el segundo socket pasivo para el protocolo de
 * management (RNF de la consigna). La infraestructura (parse de args, selector,
 * señales, shutdown) ya queda armada acá.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "args.h"
#include "selector.h"
#include "socks5.h"
#include "metrics.h"
#include "users.h"
#include "access_log.h"
#include "mgmt.h"

static volatile sig_atomic_t done = 0;
static volatile sig_atomic_t on_sig_end = 0;

static void
sigterm_handler(const int signal) {
    (void) signal;
    if (!on_sig_end) {
        on_sig_end = 1;
    } else {
        done = 1;
    }
}

/**
 * Crea un socket pasivo TCP IPv4 escuchando en addr:port.
 * Devuelve el fd, o -1 dejando el motivo en *err_msg.
 */
static int
create_passive_socket(const char *addr, unsigned short port,
                      const char **err_msg) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (addr == NULL || inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        *err_msg = "unable to create socket";
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        *err_msg = "unable to bind socket";
        close(fd);
        return -1;
    }
    if (listen(fd, 20) < 0) {
        *err_msg = "unable to listen";
        close(fd);
        return -1;
    }
    if (selector_fd_set_nio(fd) == -1) {
        *err_msg = "getting server socket flags";
        close(fd);
        return -1;
    }
    return fd;
}

int
main(const int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);

    users_init(&args);
    access_log_init(stderr);

    // no tenemos nada que leer de stdin
    close(0);

    const char     *err_msg  = NULL;
    selector_status ss       = SELECTOR_SUCCESS;
    fd_selector     selector = NULL;
    int             server   = -1;
    int             server_mng = -1;

    server = create_passive_socket(args.socks_addr, args.socks_port, &err_msg);
    if (server < 0) {
        goto finally;
    }
    fprintf(stdout, "Listening (SOCKS5) on TCP %s:%d\n",
            args.socks_addr, args.socks_port);

    server_mng = create_passive_socket(args.mng_addr, args.mng_port, &err_msg);
    if(server_mng < 0) {
        goto finally;
    }
    fprintf(stdout, "Listening (MANAGEMENT) on TCP %s:%d\n",
            args.mng_addr, args.mng_port);

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if (selector_init(&conf) != 0) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    mgmt_init(&args);

    const struct fd_handler passive = {
        .handle_read  = socks5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    ss = selector_register(selector, server, &passive, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering passive socket";
        goto finally;
    }

    const struct fd_handler passive_mng = {
        .handle_read  = mgmt_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    ss = selector_register(selector, server_mng, &passive_mng, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering management passive socket";
        goto finally;
    }

    while (!done) {
        if (on_sig_end) {
            // Dejar de aceptar nuevas conexiones en ambos sockets pasivos
            if (server >= 0) {
                selector_unregister_fd(selector, server);
                close(server);
                server = -1;
            }
            if (server_mng >= 0) {
                selector_unregister_fd(selector, server_mng);
                close(server_mng);
                server_mng = -1;
            }

            // Verificar si ya no quedan conexiones vivas
            struct metrics_snapshot snapshot;
            metrics_snapshot(&snapshot);
            if (snapshot.current_connections == 0) {
                done = 1;
                break;
            }
        }

        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    // salida normal del loop = recibimos una señal -> shutdown limpio

    int ret = 0;
finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    if (server >= 0) {
        close(server);
    }
    if (server_mng >= 0) {
        close(server_mng);
    }
    return ret;
}
