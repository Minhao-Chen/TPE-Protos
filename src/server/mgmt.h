#ifndef MGMT_H_2026C1_TPE
#define MGMT_H_2026C1_TPE

#include "selector.h"

/**
 * mgmt.h - servidor del protocolo de management (SMP) sobre el selector.
 *
 * SMP es un protocolo de texto orientado a líneas (CRLF), con sesión y
 * autenticación de administrador. Está especificado en docs/smp.md
 * (esa es la fuente única; este header es solo el punto de entrada al módulo).
 *
 * Igual que socks5.c, el lado servidor corre NO BLOQUEANTE en el mismo
 * selector; main.c crea el socket pasivo de management (en mng_addr:mng_port)
 * y registra este handler de accept. El cliente del protocolo, en cambio,
 * puede ser bloqueante.
 *
 * Lo implementa: mgmt.c. Consume:
 *   - users.h    -> users_add/del/list/count  (gestión de usuarios)
 *   - metrics.h  -> metrics_snapshot()         (GET-METRICS)
 *   - args       -> admin_user/admin_pass      (autenticación del AUTH)
 */
void
mgmt_passive_accept(struct selector_key *key);

#endif
