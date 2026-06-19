/**
 * main.c - cliente de prueba (BLOQUEANTE) para el servidor de echo.
 *
 * Es un cliente mínimo para validar la base de punta a punta: se conecta al
 * servidor, manda una línea, imprime lo que el servidor le devuelve (echo) y
 * cierra. Usa I/O bloqueante a propósito (la consigna lo permite para el
 * cliente de monitoreo, por su simpleza).
 *
 * Más adelante este binario se convertirá en el cliente del protocolo de
 * management; por ahora sirve como "hello world" cliente/servidor.
 *
 *   Uso: client [host] [port] [mensaje...]
 *   Defaults: 127.0.0.1 1080 "hola mundo"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char *port = (argc > 2) ? argv[2] : "1080";

    // arma el mensaje a partir de argv[3..] o usa el default
    char message[4096];
    if (argc > 3) {
        size_t off = 0;
        for (int i = 3; i < argc && off < sizeof(message) - 2; i++) {
            int w = snprintf(message + off, sizeof(message) - off, "%s%s",
                             (i > 3) ? " " : "", argv[i]);
            if (w < 0) break;
            off += (size_t) w;
        }
        snprintf(message + off, sizeof(message) - off, "\n");
    } else {
        strcpy(message, "hola mundo\n");
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short) atoi(port));
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "client: direccion invalida: %s\n", host);
        return 1;
    }

    const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    printf("conectado a %s:%s\n", host, port);

    const size_t len = strlen(message);
    if (send(fd, message, len, 0) != (ssize_t) len) {
        perror("send");
        close(fd);
        return 1;
    }
    printf("enviado: %s", message);

    // leemos el echo (puede llegar en partes; leemos hasta `len` bytes)
    char    reply[4096];
    size_t  got = 0;
    while (got < len) {
        const ssize_t n = recv(fd, reply + got, sizeof(reply) - got, 0);
        if (n <= 0) {
            break;
        }
        got += (size_t) n;
    }
    printf("recibido: %.*s", (int) got, reply);

    close(fd);
    printf("desconectado\n");
    return 0;
}
