#ifndef METRICS_H_2026C1_TPE
#define METRICS_H_2026C1_TPE

#include <stdint.h>

/**
 * metrics.h - métricas volátiles del servidor (requisito #6).
 *
 * Lo consumen:
 *   - socks5.c -> incrementa contadores (accept, cierre, bytes, fallos).
 *   - mgmt.c   -> lee un snapshot para el comando GET-METRICS.
 *
 * Modelo de concurrencia: un solo hilo (el del selector) -> NO hacen falta
 * locks ni atómicos. Las métricas PUEDEN ser volátiles (se pierden al
 * reiniciar), como permite la consigna.
 *
 * Puntos de incremento en socks5.c (hoy marcados con TODO(metrics)):
 *   - metrics_connection_opened()  al aceptar una conexión (passive_accept).
 *   - metrics_connection_closed()  al terminar (socksv5_done).
 *   - metrics_connection_failed()  cuando el CONNECT al origen falla.
 *   - metrics_add_bytes(n)         por cada bloque relevado en COPY.
 */

/** foto consistente de las métricas en un instante */
struct metrics_snapshot {
    uint64_t historic_connections;   /* total acumulado desde el arranque */
    uint64_t current_connections;    /* conexiones vivas en este momento */
    uint64_t bytes_transferred;      /* bytes relevados (ambos sentidos) */
    uint64_t failed_connections;     /* requests que no pudieron conectar */
};

/** una conexión fue aceptada: ++históricas, ++concurrentes */
void
metrics_connection_opened(void);

/** una conexión terminó: --concurrentes */
void
metrics_connection_closed(void);

/** una conexión no pudo establecerse contra el origen: ++fallidas */
void
metrics_connection_failed(void);

/** suma `n` bytes al total transferido */
void
metrics_add_bytes(uint64_t n);

/** copia el estado actual de las métricas en `out` */
void
metrics_snapshot(struct metrics_snapshot *out);

#endif
