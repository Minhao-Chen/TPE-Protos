#ifndef ECHO_H_2026C1_TPE
#define ECHO_H_2026C1_TPE

#include "selector.h"

/**
 * echo.c - servicio de "eco" no bloqueante de ejemplo.
 *
 * Es el caso más simple posible sobre el framework de la cátedra:
 * acepta una conexión TCP, y todo lo que el cliente escribe se lo devuelve
 * tal cual (echo). Sirve para entender el ciclo de vida de una conexión
 * (accept -> read -> write -> close) y el manejo de intereses del selector
 * antes de meternos con la máquina de estados de SOCKS5.
 *
 * Se registra como handler de lectura del socket pasivo.
 */
void
echo_passive_accept(struct selector_key *key);

#endif
