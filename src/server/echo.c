/**
 * echo.c - servicio de "eco" no bloqueante de ejemplo.
 *
 * Demuestra el flujo completo de una conexión sobre el selector:
 *
 *   1. echo_passive_accept   acepta la conexión y la registra en el selector
 *   2. echo_read             lee del socket al buffer (lecturas parciales)
 *   3. echo_write            escribe el buffer al socket (escrituras parciales)
 *   4. echo_close            libera los recursos al desregistrar el fd
 *
 * La clave de la E/S no bloqueante: nunca asumimos que un read/write mueve
 * todos los bytes. Guardamos lo que se pudo en un `buffer` y ajustamos el
 * "interés" (OP_READ / OP_WRITE) para que el selector nos vuelva a avisar
 * cuando el socket esté listo para seguir.
 */
#include <stdio.h>
#include <stdlib.h>   // malloc, free
#include <string.h>   // memset
#include <stdint.h>   // uint8_t (buffer.h lo usa pero no lo incluye)
#include <errno.h>
#include <unistd.h>   // close
#include <sys/socket.h>

#include "echo.h"
#include "buffer.h"

#define ECHO_BUFFER_SIZE 4096

/** estado por conexión */
struct echo {
    int                 client_fd;
    /** buffer único: lo que se lee del cliente se le devuelve al cliente */
    buffer              buf;
    uint8_t             raw_buf[ECHO_BUFFER_SIZE];
};

/**
 * Recalcula qué le interesa al selector de este fd:
 *   - OP_READ  si todavía hay lugar en el buffer para leer más del cliente
 *   - OP_WRITE si hay datos pendientes en el buffer para devolverle
 * Si no hay nada para leer ni escribir (no debería pasar mientras la conexión
 * vive) quedaría en OP_NOOP.
 */
static void
echo_update_interest(struct selector_key *key) {
    struct echo *e = key->data;
    fd_interest interest = OP_NOOP;

    if (buffer_can_write(&e->buf)) {
        interest |= OP_READ;   // hay espacio -> podemos leer del socket
    }
    if (buffer_can_read(&e->buf)) {
        interest |= OP_WRITE;  // hay datos  -> podemos escribir al socket
    }
    selector_set_interest_key(key, interest);
}

/** el selector avisa que el socket tiene datos para leer */
static void
echo_read(struct selector_key *key) {
    struct echo *e = key->data;

    size_t   nbytes;
    uint8_t *ptr = buffer_write_ptr(&e->buf, &nbytes);
    const ssize_t n = recv(key->fd, ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(&e->buf, n);
        echo_update_interest(key);
    } else if (n == 0) {
        // el cliente cerró su lado de escritura -> terminamos
        selector_unregister_fd(key->s, key->fd);
    } else { // n < 0
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            selector_unregister_fd(key->s, key->fd);
        }
        // EAGAIN: aviso espurio, no pasa nada, esperamos el próximo evento
    }
}

/** el selector avisa que el socket está listo para escribir */
static void
echo_write(struct selector_key *key) {
    struct echo *e = key->data;

    size_t   nbytes;
    uint8_t *ptr = buffer_read_ptr(&e->buf, &nbytes);
    const ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(&e->buf, n);
        echo_update_interest(key);
    } else if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            selector_unregister_fd(key->s, key->fd);
        }
    }
}

/** el selector avisa que el fd se desregistró: liberamos el estado */
static void
echo_close(struct selector_key *key) {
    struct echo *e = key->data;
    if (e != NULL) {
        close(e->client_fd);
        free(e);
    }
}

/** handlers de una conexión de eco ya aceptada */
static const struct fd_handler echo_handler = {
    .handle_read   = echo_read,
    .handle_write  = echo_write,
    .handle_block  = NULL,
    .handle_close  = echo_close,
};

void
echo_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len = sizeof(client_addr);
    struct echo            *state = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }

    state = malloc(sizeof(*state));
    if (state == NULL) {
        goto fail;
    }
    memset(state, 0, sizeof(*state));
    state->client_fd = client;
    buffer_init(&state->buf, ECHO_BUFFER_SIZE, state->raw_buf);

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &echo_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    fprintf(stdout, "echo: nueva conexion en fd %d\n", client);
    return;

fail:
    if (client != -1) {
        close(client);
    }
    free(state);
}
