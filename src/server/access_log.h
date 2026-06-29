#ifndef ACCESS_LOG_H_2026C1_TPE
#define ACCESS_LOG_H_2026C1_TPE

#include <stdio.h>      /* FILE */
#include <stdint.h>
#include <sys/socket.h> /* struct sockaddr */

/**
 * access_log.h - registro de accesos (requisito #8).
 *
 * Permite a un administrador saber QUIÉN se conectó, A DÓNDE y CUÁNDO
 * (caso "llega una queja externa por un acceso a cierto sitio").
 *
 * Lo consume: socks5.c (registra un acceso por cada request resuelto).
 *
 * Formato: una línea por acceso, campos separados por TAB,
 * fácil de grepear. Ej.:
 *   2026-06-29T20:15:03Z\tpablito\t10.0.0.5\texample.com:443\t0x00
 * El timestamp lo genera el propio logger; para la dirección del cliente
 * se puede reusar sockaddr_to_human() de netutils.h.
 *
 * En socks5.c: en el punto donde ya se conoce el resultado
 * (código REP), p.ej. al armar el reply (request_write_init) o tras el
 * connect (request_connect_done), pasando s->reply como `rep_status`.
 */

/**
 * Configura el destino del log (por ejemplo stderr, o un archivo abierto por
 * el servidor). Debe llamarse una vez al arrancar.
 */
void
access_log_init(FILE *out);

/**
 * Registra un acceso.
 *
 * @param username   usuario autenticado, o NULL/"-" si fue sin autenticación.
 * @param client     dirección del cliente que originó la conexión.
 * @param atyp       tipo de destino pedido (ATYP de SOCKS5: 0x01/0x03/0x04).
 * @param dest_addr  destino en texto (FQDN si fue dominio, o IP en texto).
 * @param dest_port  puerto destino, en host order.
 * @param rep_status código REP enviado al cliente (0x00 = éxito).
 */
void
access_log_record(const char *username,
                  const struct sockaddr *client,
                  uint8_t atyp,
                  const char *dest_addr,
                  uint16_t dest_port,
                  uint8_t rep_status);

#endif
