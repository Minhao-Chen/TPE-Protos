#ifndef SOCKS5_H_2026C1_TPE
#define SOCKS5_H_2026C1_TPE

#include "selector.h"

/**
 * socks5.c - máquina de estados de una conexión proxy SOCKS5
 *            (RFC1928 + sub-negociación user/pass RFC1929), sobre el
 *            selector no bloqueante de la cátedra.
 *
 * El flujo de una conexión se modela con el `stm` de la cátedra:
 *
 *   HELLO_READ -> HELLO_WRITE -> [AUTH_READ -> AUTH_WRITE] ->
 *   REQUEST_READ -> (REQUEST_RESOLV) -> REQUEST_CONNECT ->
 *   REQUEST_WRITE -> COPY -> DONE
 *
 * Una sola estructura `struct socks5` por conexión es compartida por el
 * socket del cliente y el del origen (con conteo de referencias).
 *
 * Este es el handler de lectura del socket pasivo SOCKS5: acepta la
 * conexión entrante, crea el estado y arranca la máquina.
 */
void
socks5_passive_accept(struct selector_key *key);

#endif
