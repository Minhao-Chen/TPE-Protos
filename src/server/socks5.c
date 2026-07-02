/**
 * socks5.c - máquina de estados de una conexión proxy SOCKS5 (RFC1928 / RFC1929).
 *
 * Toda la conexión vive sobre el selector no bloqueante: cada fase del
 * protocolo es un estado del `stm` de la cátedra. La E/S se hace siempre
 * contra los `buffer` (tolerante a lecturas/escrituras parciales) y el
 * "interés" (OP_READ/OP_WRITE) se recalcula en cada paso.
 *
 * Puntos de integración con los otros módulos:
 *   - users.c: validación real de credenciales en AUTH.
 *   - metrics.c: contadores de conexiones y bytes.
 *   - access_log: registro de accesos.
 * Mientras esos módulos no existan, el archivo es self-contained y funcional
 * para el método NO-AUTH (la auth user/pass acepta provisoriamente, ver
 * socks5_auth_check).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "buffer.h"
#include "stm.h"
#include "selector.h"
#include "socks5.h"
#include "users.h"
#include "metrics.h"

#define N(x)            (sizeof(x)/sizeof((x)[0]))
#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

#define BUFFER_SIZE 4096

/* ---- constantes del protocolo (RFC1928 / RFC1929) ---- */
#define SOCKS5_VERSION 0x05
#define AUTH_VERSION   0x01   /* versión de la sub-negociación user/pass */

/* métodos de autenticación */
#define METHOD_NO_AUTH       0x00
#define METHOD_USERPASS      0x02
#define METHOD_NO_ACCEPTABLE 0xFF

/* comandos */
#define CMD_CONNECT       0x01
#define CMD_BIND          0x02
#define CMD_UDP_ASSOCIATE 0x03

/* tipos de dirección */
#define ATYP_IPV4   0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6   0x04

/* códigos de respuesta (REP) */
#define REP_SUCCESS               0x00
#define REP_GENERAL_FAILURE       0x01
#define REP_CONN_NOT_ALLOWED      0x02
#define REP_NETWORK_UNREACHABLE   0x03
#define REP_HOST_UNREACHABLE      0x04
#define REP_CONNECTION_REFUSED    0x05
#define REP_TTL_EXPIRED           0x06
#define REP_COMMAND_NOT_SUPPORTED 0x07
#define REP_ATYP_NOT_SUPPORTED    0x08

/* estado de la sub-negociación user/pass */
#define AUTH_STATUS_OK   0x00
#define AUTH_STATUS_FAIL 0x01

/** resultado de los parsers incrementales */
enum parse_result {
    PARSE_INCOMPLETE,  /* faltan bytes; volver a leer */
    PARSE_DONE,        /* mensaje completo */
    PARSE_ERROR,       /* violación de protocolo */
};

/** estados de la máquina (el orden DEBE coincidir con socks5_statbl) */
enum socks5_state {
    HELLO_READ = 0,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECT,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
};

/* ------------------------------------------------------------------ */
/* estado por fase                                                     */
/* ------------------------------------------------------------------ */

/** HELLO: VER | NMETHODS | METHODS[] */
struct hello_st {
    enum { HELLO_ST_VERSION, HELLO_ST_NMETHODS, HELLO_ST_METHODS } state;
    uint8_t remaining;       /* métodos que faltan leer */
    bool    noauth_seen;
    bool    userpass_seen;
    uint8_t method;          /* método elegido para responder */
};

/** AUTH (RFC1929): VER | ULEN | UNAME | PLEN | PASSWD */
struct auth_st {
    enum { AUTH_ST_VERSION, AUTH_ST_ULEN, AUTH_ST_UNAME,
           AUTH_ST_PLEN, AUTH_ST_PASSWD } state;
    uint8_t ulen, uread;
    uint8_t plen, pread;
    char    uname[256];
    char    passwd[256];
    uint8_t status;
};

/** REQUEST: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT */
struct request_st {
    enum { REQ_ST_VERSION, REQ_ST_CMD, REQ_ST_RSV, REQ_ST_ATYP,
           REQ_ST_ADDR_LEN, REQ_ST_ADDR, REQ_ST_PORT } state;
    uint8_t  cmd, atyp;
    uint8_t  addr_len;      /* bytes esperados de DST.ADDR */
    uint8_t  addr_read;
    uint8_t  addr[256];
    uint8_t  port_read;
    uint16_t port;          /* en host order */
};

/**
 * Estado completo de una conexión. Una sola alocación por conexión.
 * La comparten client_fd y origin_fd; `references` decide cuándo liberar.
 *
 * Convención de buffers:
 *   read_buffer  : bytes que LEEMOS del cliente   (sentido client -> origin)
 *   write_buffer : bytes que ESCRIBIMOS al cliente (sentido origin -> client)
 */
struct socks5 {
    int                     client_fd;
    int                     origin_fd;
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;

    struct state_machine    stm;
    unsigned                references;

    struct hello_st         hello;
    struct auth_st          auth;
    struct request_st       request;

    /* resolución / conexión al origen */
    struct addrinfo        *origin_resolution;  /* lista de getaddrinfo */
    struct addrinfo        *origin_next;          /* cursor de reintentos */
    int                     origin_domain;
    bool                    resolution_failed;
    char                    fqdn[256];
    uint16_t                dst_port;             /* host order */

    uint8_t                 reply;                /* REP a enviar */

    /* half-close del relay */
    bool                    client_eof;
    bool                    origin_eof;

    buffer                  read_buffer;
    buffer                  write_buffer;
    uint8_t                 raw_read [BUFFER_SIZE];
    uint8_t                 raw_write[BUFFER_SIZE];
};

/* ------------------------------------------------------------------ */
/* forward declarations                                                */
/* ------------------------------------------------------------------ */
static void     socksv5_read (struct selector_key *key);
static void     socksv5_write(struct selector_key *key);
static void     socksv5_block(struct selector_key *key);
static void     socksv5_close(struct selector_key *key);
static void     socksv5_done (struct selector_key *key);

static unsigned hello_read   (struct selector_key *key);
static void     hello_write_init(unsigned state, struct selector_key *key);
static unsigned hello_write  (struct selector_key *key);
static void     auth_read_init(unsigned state, struct selector_key *key);
static unsigned auth_read    (struct selector_key *key);
static void     auth_write_init(unsigned state, struct selector_key *key);
static unsigned auth_write   (struct selector_key *key);
static void     request_read_init(unsigned state, struct selector_key *key);
static unsigned request_read (struct selector_key *key);
static void     request_resolv_init(unsigned state, struct selector_key *key);
static unsigned request_resolv_done(struct selector_key *key);
static void     request_connect_init(unsigned state, struct selector_key *key);
static unsigned request_connect_done(struct selector_key *key);
static void     request_write_init(unsigned state, struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void     copy_init    (unsigned state, struct selector_key *key);
static unsigned copy_read    (struct selector_key *key);
static unsigned copy_write   (struct selector_key *key);

static unsigned connect_list (struct selector_key *key, struct socks5 *s);
static bool     connect_attempt(struct selector_key *key, struct socks5 *s,
                                int family, const struct sockaddr *addr,
                                socklen_t len);

/** handler de selección compartido por client_fd y origin_fd */
static const struct fd_handler socks5_handler = {
    .handle_read  = socksv5_read,
    .handle_write = socksv5_write,
    .handle_block = socksv5_block,
    .handle_close = socksv5_close,
};

/** tabla de estados (índice == .state) */
static const struct state_definition socks5_statbl[] = {
    { .state = HELLO_READ,      .on_read_ready  = hello_read,           },
    { .state = HELLO_WRITE,     .on_arrival     = hello_write_init,
                                .on_write_ready = hello_write,          },
    { .state = AUTH_READ,       .on_arrival     = auth_read_init,
                                .on_read_ready  = auth_read,            },
    { .state = AUTH_WRITE,      .on_arrival     = auth_write_init,
                                .on_write_ready = auth_write,           },
    { .state = REQUEST_READ,    .on_arrival     = request_read_init,
                                .on_read_ready  = request_read,         },
    { .state = REQUEST_RESOLV,  .on_arrival     = request_resolv_init,
                                .on_block_ready = request_resolv_done,  },
    { .state = REQUEST_CONNECT, .on_arrival     = request_connect_init,
                                .on_write_ready = request_connect_done, },
    { .state = REQUEST_WRITE,   .on_arrival     = request_write_init,
                                .on_write_ready = request_write,        },
    { .state = COPY,            .on_arrival     = copy_init,
                                .on_read_ready  = copy_read,
                                .on_write_ready = copy_write,           },
    { .state = DONE,                                                    },
    { .state = ERROR,                                                   },
};

/* ------------------------------------------------------------------ */
/* ciclo de vida                                                       */
/* ------------------------------------------------------------------ */

static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *s = malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    memset(s, 0, sizeof(*s));
    s->client_fd      = client_fd;
    s->origin_fd      = -1;
    s->references     = 1;
    s->reply          = REP_SUCCESS;

    s->stm.initial    = HELLO_READ;
    s->stm.max_state  = ERROR;
    s->stm.states     = socks5_statbl;
    stm_init(&s->stm);

    buffer_init(&s->read_buffer,  BUFFER_SIZE, s->raw_read);
    buffer_init(&s->write_buffer, BUFFER_SIZE, s->raw_write);
    return s;
}

/** libera teniendo en cuenta el conteo de referencias (los 2 fds comparten s) */
static void
socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    if (s->references > 1) {
        s->references--;
        return;
    }
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
    }
    free(s);
}

/* ------------------------------------------------------------------ */
/* socket pasivo + handlers top-level                                  */
/* ------------------------------------------------------------------ */

void
socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len = sizeof(client_addr);
    struct socks5          *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if (state == NULL) {
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    metrics_connection_opened();
    return;

fail:
    if (client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

static void
socksv5_read(struct selector_key *key) {
    struct state_machine  *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_read(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine  *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_write(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine  *stm = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_block(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

/** se invoca al desregistrar cada fd: descuenta una referencia */
static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

/** desregistra y cierra ambos fds de la conexión */
static void
socksv5_done(struct selector_key *key) {
    metrics_connection_closed();
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            selector_unregister_fd(key->s, fds[i]);  /* dispara socksv5_close */
            close(fds[i]);
        }
    }
}

/* ------------------------------------------------------------------ */
/* HELLO                                                               */
/* ------------------------------------------------------------------ */

static enum parse_result
hello_select(struct hello_st *h) {
    /* política provisoria: preferimos NO-AUTH; el requerimiento de auth
     * obligatoria será una decisión de config + users.c. */
    if (h->noauth_seen) {
        h->method = METHOD_NO_AUTH;
    } else if (h->userpass_seen) {
        h->method = METHOD_USERPASS;
    } else {
        h->method = METHOD_NO_ACCEPTABLE;
    }
    return PARSE_DONE;
}

static enum parse_result
hello_parse(struct socks5 *s) {
    struct hello_st *h = &s->hello;
    while (buffer_can_read(&s->read_buffer)) {
        const uint8_t c = buffer_read(&s->read_buffer);
        switch (h->state) {
            case HELLO_ST_VERSION:
                if (c != SOCKS5_VERSION) {
                    return PARSE_ERROR;
                }
                h->state = HELLO_ST_NMETHODS;
                break;
            case HELLO_ST_NMETHODS:
                h->remaining = c;
                if (h->remaining == 0) {
                    return hello_select(h);
                }
                h->state = HELLO_ST_METHODS;
                break;
            case HELLO_ST_METHODS:
                if (c == METHOD_NO_AUTH) {
                    h->noauth_seen = true;
                } else if (c == METHOD_USERPASS) {
                    h->userpass_seen = true;
                }
                if (--h->remaining == 0) {
                    return hello_select(h);
                }
                break;
        }
    }
    return PARSE_INCOMPLETE;
}

static unsigned
hello_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &count);
    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return HELLO_READ;
        }
        return ERROR;
    }
    buffer_write_adv(&s->read_buffer, n);

    switch (hello_parse(s)) {
        case PARSE_INCOMPLETE: return HELLO_READ;
        case PARSE_DONE:       return HELLO_WRITE;
        default:               return ERROR;
    }
}

static void
hello_write_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    buffer_write(&s->write_buffer, SOCKS5_VERSION);
    buffer_write(&s->write_buffer, s->hello.method);
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
}

static unsigned
hello_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &count);
    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? HELLO_WRITE : ERROR;
    }
    buffer_read_adv(&s->write_buffer, n);
    if (buffer_can_read(&s->write_buffer)) {
        return HELLO_WRITE;
    }
    /* respuesta enviada por completo */
    if (s->hello.method == METHOD_NO_ACCEPTABLE) {
        return ERROR;                 /* RFC1928: el cliente debe cerrar */
    }
    return (s->hello.method == METHOD_USERPASS) ? AUTH_READ : REQUEST_READ;
}

/* ------------------------------------------------------------------ */
/* AUTH (RFC1929)                                                      */
/* ------------------------------------------------------------------ */

static bool
socks5_auth_check(const char *user, const char *pass) {
    return users_login(user, pass);
}

static enum parse_result
auth_parse(struct socks5 *s) {
    struct auth_st *a = &s->auth;
    while (buffer_can_read(&s->read_buffer)) {
        const uint8_t c = buffer_read(&s->read_buffer);
        switch (a->state) {
            case AUTH_ST_VERSION:
                if (c != AUTH_VERSION) {
                    return PARSE_ERROR;
                }
                a->state = AUTH_ST_ULEN;
                break;
            case AUTH_ST_ULEN:
                a->ulen  = c;
                a->uread = 0;
                a->state = (c == 0) ? AUTH_ST_PLEN : AUTH_ST_UNAME;
                break;
            case AUTH_ST_UNAME:
                a->uname[a->uread++] = (char) c;
                if (a->uread >= a->ulen) {
                    a->uname[a->uread] = '\0';
                    a->state = AUTH_ST_PLEN;
                }
                break;
            case AUTH_ST_PLEN:
                a->plen  = c;
                a->pread = 0;
                if (c == 0) {
                    a->passwd[0] = '\0';
                    return PARSE_DONE;
                }
                a->state = AUTH_ST_PASSWD;
                break;
            case AUTH_ST_PASSWD:
                a->passwd[a->pread++] = (char) c;
                if (a->pread >= a->plen) {
                    a->passwd[a->pread] = '\0';
                    return PARSE_DONE;
                }
                break;
        }
    }
    return PARSE_INCOMPLETE;
}

static void
auth_read_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    s->auth.uname[0] = '\0';
    s->auth.passwd[0] = '\0';
    selector_set_interest(key->s, s->client_fd, OP_READ);
}

static unsigned
auth_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &count);
    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return AUTH_READ;
        }
        return ERROR;
    }
    buffer_write_adv(&s->read_buffer, n);

    switch (auth_parse(s)) {
        case PARSE_INCOMPLETE:
            return AUTH_READ;
        case PARSE_DONE:
            s->auth.status = socks5_auth_check(s->auth.uname, s->auth.passwd)
                             ? AUTH_STATUS_OK : AUTH_STATUS_FAIL;
            return AUTH_WRITE;
        default:
            return ERROR;
    }
}

static void
auth_write_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    buffer_write(&s->write_buffer, AUTH_VERSION);
    buffer_write(&s->write_buffer, s->auth.status);
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
}

static unsigned
auth_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &count);
    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? AUTH_WRITE : ERROR;
    }
    buffer_read_adv(&s->write_buffer, n);
    if (buffer_can_read(&s->write_buffer)) {
        return AUTH_WRITE;
    }
    /* RFC1929: si STATUS != 0 el servidor DEBE cerrar la conexión */
    return (s->auth.status == AUTH_STATUS_OK) ? REQUEST_READ : ERROR;
}

/* ------------------------------------------------------------------ */
/* REQUEST                                                             */
/* ------------------------------------------------------------------ */

static uint8_t
errno_to_socks_rep(int e) {
    switch (e) {
        case ECONNREFUSED: return REP_CONNECTION_REFUSED;
        case ENETUNREACH:  return REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH: return REP_HOST_UNREACHABLE;
        case ETIMEDOUT:    return REP_TTL_EXPIRED;
        default:           return REP_GENERAL_FAILURE;
    }
}

static enum parse_result
request_parse(struct socks5 *s) {
    struct request_st *r = &s->request;
    while (buffer_can_read(&s->read_buffer)) {
        const uint8_t c = buffer_read(&s->read_buffer);
        switch (r->state) {
            case REQ_ST_VERSION:
                if (c != SOCKS5_VERSION) {
                    return PARSE_ERROR;
                }
                r->state = REQ_ST_CMD;
                break;
            case REQ_ST_CMD:
                r->cmd   = c;
                r->state = REQ_ST_RSV;
                break;
            case REQ_ST_RSV:
                r->state = REQ_ST_ATYP;    /* RSV se ignora */
                break;
            case REQ_ST_ATYP:
                r->atyp      = c;
                r->addr_read = 0;
                if (c == ATYP_IPV4) {
                    r->addr_len = 4;
                    r->state    = REQ_ST_ADDR;
                } else if (c == ATYP_IPV6) {
                    r->addr_len = 16;
                    r->state    = REQ_ST_ADDR;
                } else if (c == ATYP_DOMAIN) {
                    r->state    = REQ_ST_ADDR_LEN;
                } else {
                    s->reply = REP_ATYP_NOT_SUPPORTED;  /* error reportable */
                    return PARSE_ERROR;
                }
                break;
            case REQ_ST_ADDR_LEN:
                if (c == 0) {
                    return PARSE_ERROR;
                }
                r->addr_len = c;
                r->state    = REQ_ST_ADDR;
                break;
            case REQ_ST_ADDR:
                r->addr[r->addr_read++] = c;
                if (r->addr_read >= r->addr_len) {
                    r->port      = 0;
                    r->port_read = 0;
                    r->state     = REQ_ST_PORT;
                }
                break;
            case REQ_ST_PORT:
                r->port = (uint16_t) ((r->port << 8) | c);
                if (++r->port_read >= 2) {
                    return PARSE_DONE;
                }
                break;
        }
    }
    return PARSE_INCOMPLETE;
}

static void
request_read_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    selector_set_interest(key->s, s->client_fd, OP_READ);
}

static unsigned
request_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &count);
    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return REQUEST_READ;
        }
        return ERROR;
    }
    buffer_write_adv(&s->read_buffer, n);

    const enum parse_result pr = request_parse(s);
    if (pr == PARSE_INCOMPLETE) {
        return REQUEST_READ;
    }
    if (pr == PARSE_ERROR) {
        /* si seteamos un REP reportable (ej. ATYP), mandamos respuesta;
         * si fue una violación dura (VER), cerramos. */
        return (s->reply != REP_SUCCESS) ? REQUEST_WRITE : ERROR;
    }

    /* PARSE_DONE */
    if (s->request.cmd != CMD_CONNECT) {
        s->reply = REP_COMMAND_NOT_SUPPORTED;
        return REQUEST_WRITE;
    }
    s->dst_port = s->request.port;

    /* TODO(access_log): registrar (usuario, destino, timestamp). */

    if (s->request.atyp == ATYP_DOMAIN) {
        memcpy(s->fqdn, s->request.addr, s->request.addr_len);
        s->fqdn[s->request.addr_len] = '\0';
        return REQUEST_RESOLV;
    }

    /* IP literal: armamos el sockaddr e intentamos conectar directo */
    if (s->request.atyp == ATYP_IPV4) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port   = htons(s->dst_port);
        memcpy(&sin.sin_addr, s->request.addr, 4);
        if (connect_attempt(key, s, AF_INET, (struct sockaddr *) &sin,
                            sizeof(sin))) {
            return REQUEST_CONNECT;
        }
        metrics_connection_failed();
        return REQUEST_WRITE;
    } else {  /* ATYP_IPV6 */
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port   = htons(s->dst_port);
        memcpy(&sin6.sin6_addr, s->request.addr, 16);
        if (connect_attempt(key, s, AF_INET6, (struct sockaddr *) &sin6,
                            sizeof(sin6))) {
            return REQUEST_CONNECT;
        }
        metrics_connection_failed();
        return REQUEST_WRITE;
    }
}

/* ---- resolución de nombres en hilo aparte (única excepción permitida) ---- */

static void *
dns_resolve_thread(void *arg) {
    struct selector_key *key = arg;
    struct socks5       *s   = ATTACHMENT(key);
    pthread_detach(pthread_self());

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned) s->dst_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;     /* IPv4 e IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(s->fqdn, port_str, &hints, &s->origin_resolution) != 0) {
        s->resolution_failed = true;
        s->origin_resolution = NULL;
    }
    selector_notify_block(key->s, key->fd);
    free(key);
    return NULL;
}

static void
request_resolv_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    /* mientras resuelve no nos interesa ningún evento del socket del cliente */
    selector_set_interest(key->s, s->client_fd, OP_NOOP);

    struct selector_key *blocking = malloc(sizeof(*blocking));
    if (blocking == NULL) {
        s->resolution_failed = true;
        selector_notify_block(key->s, key->fd);
        return;
    }
    memcpy(blocking, key, sizeof(*blocking));

    pthread_t tid;
    if (pthread_create(&tid, NULL, dns_resolve_thread, blocking) != 0) {
        free(blocking);
        s->resolution_failed = true;
        selector_notify_block(key->s, key->fd);
    }
}

static unsigned
request_resolv_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    if (s->resolution_failed || s->origin_resolution == NULL) {
        s->reply = REP_HOST_UNREACHABLE;
        metrics_connection_failed();
        return REQUEST_WRITE;
    }
    s->origin_next = s->origin_resolution;
    return connect_list(key, s);
}

/* ---- conexión no bloqueante al origen, con fallback multi-dirección ---- */

/** intenta UNA dirección; true si quedó conectando (origin registrado) */
static bool
connect_attempt(struct selector_key *key, struct socks5 *s,
                int family, const struct sockaddr *addr, socklen_t len) {
    const int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        s->reply = REP_GENERAL_FAILURE;
        return false;
    }
    if (selector_fd_set_nio(fd) < 0) {
        close(fd);
        s->reply = REP_GENERAL_FAILURE;
        return false;
    }
    if (connect(fd, addr, len) == 0 || errno == EINPROGRESS) {
        if (selector_register(key->s, fd, &socks5_handler, OP_WRITE, s)
                != SELECTOR_SUCCESS) {
            close(fd);
            s->reply = REP_GENERAL_FAILURE;
            return false;
        }
        s->origin_fd     = fd;
        s->origin_domain = family;
        s->references++;
        return true;
    }
    s->reply = errno_to_socks_rep(errno);
    close(fd);
    return false;
}

/** recorre la lista de getaddrinfo probando direcciones (req. de robustez) */
static unsigned
connect_list(struct selector_key *key, struct socks5 *s) {
    while (s->origin_next != NULL) {
        struct addrinfo *ai = s->origin_next;
        s->origin_next = ai->ai_next;
        if (connect_attempt(key, s, ai->ai_family, ai->ai_addr,
                            ai->ai_addrlen)) {
            return REQUEST_CONNECT;
        }
    }
    if (s->reply == REP_SUCCESS) {
        s->reply = REP_HOST_UNREACHABLE;
    }
    metrics_connection_failed();
    return REQUEST_WRITE;
}

static void
request_connect_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    /* esperamos a que el socket del origen sea escribible (connect listo) */
    selector_set_interest(key->s, s->client_fd, OP_NOOP);
}

static unsigned
request_connect_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    int       error = 0;
    socklen_t len   = sizeof(error);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        error = errno;
    }
    if (error == 0) {
        s->reply = REP_SUCCESS;
        return REQUEST_WRITE;
    }

    /* falló esta dirección: cerrar y probar la siguiente (si la hay) */
    s->reply = errno_to_socks_rep(error);
    selector_unregister_fd(key->s, s->origin_fd);  /* descuenta referencia */
    close(s->origin_fd);
    s->origin_fd = -1;

    if (s->origin_next != NULL) {
        return connect_list(key, s);
    }
    metrics_connection_failed();
    return REQUEST_WRITE;
}

/* ---- envío del reply al cliente ---- */

static void
push_addr_port(buffer *b, const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *) ss;
        const uint8_t *a = (const uint8_t *) &in->sin_addr.s_addr;
        const uint8_t *p = (const uint8_t *) &in->sin_port;
        buffer_write(b, ATYP_IPV4);
        for (int i = 0; i < 4; i++) buffer_write(b, a[i]);
        buffer_write(b, p[0]);
        buffer_write(b, p[1]);
    } else {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) ss;
        const uint8_t *a = (const uint8_t *) &in6->sin6_addr;
        const uint8_t *p = (const uint8_t *) &in6->sin6_port;
        buffer_write(b, ATYP_IPV6);
        for (int i = 0; i < 16; i++) buffer_write(b, a[i]);
        buffer_write(b, p[0]);
        buffer_write(b, p[1]);
    }
}

static void
request_write_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    buffer *b = &s->write_buffer;

    buffer_write(b, SOCKS5_VERSION);
    buffer_write(b, s->reply);
    buffer_write(b, 0x00);  /* RSV */

    struct sockaddr_storage bnd;
    socklen_t               bnd_len = sizeof(bnd);
    if (s->reply == REP_SUCCESS && s->origin_fd != -1
        && getsockname(s->origin_fd, (struct sockaddr *) &bnd, &bnd_len) == 0
        && (bnd.ss_family == AF_INET || bnd.ss_family == AF_INET6)) {
        push_addr_port(b, &bnd);
    } else {
        buffer_write(b, ATYP_IPV4);          /* BND 0.0.0.0:0 */
        for (int i = 0; i < 6; i++) buffer_write(b, 0x00);
    }

    selector_set_interest(key->s, s->client_fd, OP_WRITE);
    if (s->origin_fd != -1) {
        selector_set_interest(key->s, s->origin_fd, OP_NOOP);
    }
}

static unsigned
request_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    size_t   count;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &count);
    const ssize_t n = send(s->client_fd, ptr, count, MSG_NOSIGNAL);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? REQUEST_WRITE : ERROR;
    }
    buffer_read_adv(&s->write_buffer, n);
    if (buffer_can_read(&s->write_buffer)) {
        return REQUEST_WRITE;
    }
    /* reply enviado: si fue éxito arrancamos el relay; si no, cerramos */
    return (s->reply == REP_SUCCESS) ? COPY : DONE;
}

/* ------------------------------------------------------------------ */
/* COPY (relay bidireccional)                                          */
/* ------------------------------------------------------------------ */

static void
copy_compute_interests(fd_selector sel, struct socks5 *s) {
    fd_interest ci = OP_NOOP;
    fd_interest oi = OP_NOOP;

    if (!s->client_eof && buffer_can_write(&s->read_buffer)) {
        ci |= OP_READ;                       /* leer del cliente */
    }
    if (buffer_can_read(&s->write_buffer)) {
        ci |= OP_WRITE;                      /* escribir al cliente */
    }
    if (!s->origin_eof && buffer_can_write(&s->write_buffer)) {
        oi |= OP_READ;                       /* leer del origen */
    }
    if (buffer_can_read(&s->read_buffer)) {
        oi |= OP_WRITE;                      /* escribir al origen */
    }
    selector_set_interest(sel, s->client_fd, ci);
    if (s->origin_fd != -1) {
        selector_set_interest(sel, s->origin_fd, oi);
    }
}

static void
copy_init(unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);
    s->client_eof = false;
    s->origin_eof = false;
    copy_compute_interests(key->s, s);
}

/** maneja shutdowns por half-close y decide terminación; recalcula intereses */
static unsigned
copy_after_io(struct selector_key *key, struct socks5 *s) {
    if (s->client_eof && !buffer_can_read(&s->read_buffer)
        && s->origin_fd != -1) {
        shutdown(s->origin_fd, SHUT_WR);
    }
    if (s->origin_eof && !buffer_can_read(&s->write_buffer)) {
        shutdown(s->client_fd, SHUT_WR);
    }

    const bool c2o_done = s->client_eof && !buffer_can_read(&s->read_buffer);
    const bool o2c_done = s->origin_eof && !buffer_can_read(&s->write_buffer);
    if (c2o_done && o2c_done) {
        return DONE;
    }
    copy_compute_interests(key->s, s);
    return COPY;
}

static unsigned
copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    /* cliente -> read_buffer ; origen -> write_buffer */
    buffer *b = (key->fd == s->client_fd) ? &s->read_buffer : &s->write_buffer;

    size_t   count;
    uint8_t *ptr = buffer_write_ptr(b, &count);
    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(b, n);
        metrics_add_bytes(n);
    } else if (n == 0) {
        if (key->fd == s->client_fd) {
            s->client_eof = true;
        } else {
            s->origin_eof = true;
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return ERROR;
    }
    return copy_after_io(key, s);
}

static unsigned
copy_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    /* al cliente le mandamos write_buffer ; al origen le mandamos read_buffer */
    buffer *b = (key->fd == s->client_fd) ? &s->write_buffer : &s->read_buffer;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(b, &count);
    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n > 0) {
        buffer_read_adv(b, n);
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return ERROR;
    }
    return copy_after_io(key, s);
}
