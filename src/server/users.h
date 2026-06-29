#ifndef USERS_H_2026C1_TPE
#define USERS_H_2026C1_TPE

#include <stdbool.h>
#include <stddef.h>

#include "args.h"   /* struct socks5args (carga inicial de los -u) */

/**
 * users.h - registro de usuarios del proxy (autenticación user/pass, RFC1929).
 *
 * Lo consumen:
 *   - socks5.c  -> users_login()  en el estado AUTH.
 *   - mgmt.c    -> users_add/del/list/count  desde el protocolo de management.
 *
 * Modelo de concurrencia: todo corre en el hilo del selector, así que NO hace
 * falta sincronización. El hilo de resolución de DNS no toca este módulo.
 *
 * Nota sobre las credenciales: las tratamos como C-strings (NUL-terminated).
 * Es consistente con el parser de args (`name:pass`) y con el protocolo de
 * management (texto). UNAME/PASSWD de RFC1929 pueden ser hasta 255 octetos;
 * socks5.c los recibe y los NUL-termina antes de llamar a users_login().
 */

/** máximo de usuarios simultáneos (coincide con MAX_USERS de args.h) */
#define USERS_MAX       10
/** longitudes máximas (RFC1929: ULEN/PLEN son de 1 octeto -> hasta 255) */
#define USERS_NAME_MAX  255
#define USERS_PASS_MAX  255

/** resultado de las operaciones de administración de usuarios */
enum users_result {
    USERS_OK = 0,    /* operación exitosa */
    USERS_FULL,      /* se alcanzó USERS_MAX */
    USERS_DUP,       /* el usuario ya existe (add) */
    USERS_NOTFOUND,  /* el usuario no existe (del) */
    USERS_BADREQ,    /* nombre/clave inválidos (vacío, muy largo, etc.) */
};

/** vista de sólo lectura de un usuario (para listar sin exponer el password) */
struct user_view {
    const char *name;
};

/**
 * Inicializa el registro a partir de los usuarios pasados por línea de
 * comandos (-u name:pass). Debe llamarse una sola vez al arrancar, antes de
 * atender conexiones.
 */
void
users_init(const struct socks5args *args);

/**
 * Verifica credenciales. Devuelve true si (name, pass) es un usuario válido.
 * Lo usa el estado AUTH de socks5.c.
 */
bool
users_login(const char *name, const char *pass);

/**
 * Da de alta un usuario. Falla si ya existe (USERS_DUP), si no hay lugar
 * (USERS_FULL) o si los datos son inválidos (USERS_BADREQ).
 */
enum users_result
users_add(const char *name, const char *pass);

/**
 * Da de baja un usuario por nombre. USERS_NOTFOUND si no existe.
 */
enum users_result
users_del(const char *name);

/**
 * Copia hasta `max` usuarios en `out` y devuelve la cantidad efectivamente
 * escrita. Útil para el comando LIST-USERS del management.
 */
size_t
users_list(struct user_view *out, size_t max);

/** cantidad actual de usuarios registrados */
size_t
users_count(void);

#endif
