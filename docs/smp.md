# SMP — SOCKS5 Management Protocol (v1.0)

Especificación del protocolo de monitoreo y administración del proxy SOCKS5
(requisito funcional #7 y no-funcional #5). Permite gestionar usuarios, leer
métricas y cambiar configuración **en tiempo de ejecución, sin reiniciar** el
servidor. Escucha en un socket pasivo propio, distinto del de SOCKS5
(default `127.0.0.1:8080`).

> Esta descripción es agnóstica al lenguaje: contiene todo lo necesario para
> reimplementar cliente y servidor. (Insumo directo de la sección "protocolo
> estilo RFC" del informe.)

## 1. Transporte y codificación

- **Transporte:** TCP.
- **Lado servidor:** NO bloqueante, multiplexado en el mismo selector que el
  proxy (es "otro socket pasivo en el mismo programa"). **Lado cliente:** puede
  ser bloqueante (la consigna lo permite por su simpleza).
- **Encuadre:** orientado a **líneas terminadas en CRLF** (`\r\n`).
- **Codificación:** ASCII / UTF-8.
- **Comandos:** *case-insensitive*. Argumentos separados por **un** espacio
  (`SP`, 0x20).
- **Límite de línea:** 1024 octetos incluido el CRLF. Si se excede sin CRLF, el
  servidor responde `413` y cierra la conexión. *(Acota el uso de memoria: sin
  límite, un cliente podría mandar una línea infinita.)*

## 2. Modelo de sesión

```
   connect ──▶ el servidor envía  "220 ..."
                     │
                     ▼
            ┌──────────────────┐   AUTH ok (250)   ┌──────────────────┐
            │      UNAUTH       │ ────────────────▶ │      READY        │
            │ permite: AUTH,    │                   │ permite: todos    │
            │ HELP, PING, QUIT  │ ◀── AUTH fail ─── │ los comandos      │
            └─────────┬─────────┘    (401, sigue)   └─────────┬─────────┘
                      │ QUIT / timeout / error                │ QUIT
                      ▼                                         ▼
                   CLOSED ◀────────────────────────────────  CLOSED
```

La sesión arranca **no autenticada**. Solo tras un `AUTH` exitoso se habilitan
los demás comandos. Un `AUTH` fallido responde `401` y la sesión sigue
no autenticada (se puede reintentar).

## 3. Autenticación

Credencial de **administrador dedicada**, configurada en el servidor por línea
de comandos: `-t <user>:<pass>` (default de desarrollo `admin:admin`, cambiar
con `-t`). Es independiente de los usuarios del proxy SOCKS (`-u`).

Comando: `AUTH <user> <pass>` → `250 OK` habilita la sesión.

## 4. Sintaxis (ABNF, RFC 5234)

```abnf
session     = greeting *exchange
greeting    = "220" SP text CRLF
exchange    = command response

command     = verb *( SP arg ) CRLF
verb        = 1*( ALPHA / "-" )          ; ADD-USER, GET-METRICS, ...
arg         = 1*pchar                     ; sin espacios ni CR/LF
pchar       = %x21-7E                      ; imprimibles
                                           ; user/pass: 1..255 pchar

response    = status-line *value-line
status-line = code SP text CRLF
code        = 3DIGIT
value-line  = 1*pchar CRLF                 ; solo en respuestas con lista
CRLF        = %d13 %d10
SP          = %d32
```

**Respuestas con lista** (p. ej. `LIST-USERS`): la `status-line` trae el
**conteo** en `text` y a continuación van exactamente esa cantidad de
`value-line`. Así el cliente sabe cuántas líneas leer, sin terminadores ni
escaping.

## 5. Comandos

| Comando | Args | Requiere auth | Respuesta OK | Errores |
|---|---|:---:|---|---|
| `AUTH` | `<user> <pass>` | — | `250 OK` | `401`, `400` |
| `ADD-USER` | `<name> <pass>` | sí | `250 OK` | `409`, `507`, `400`, `401` |
| `DEL-USER` | `<name>` | sí | `250 OK` | `404`, `401` |
| `LIST-USERS` | — | sí | `250 <count>` + `<count>` líneas (un nombre c/u) | `401` |
| `GET-METRICS` | — | sí | `250 historic=<n> current=<n> bytes=<n> failed=<n>` | `401` |
| `GET` | `<key>` | sí | `250 <key>=<value>` | `404`, `401` |
| `SET` | `<key> <value>` | sí | `250 OK` | `404`, `400`, `401` |
| `HELP` | — | — | `250 ...` | — |
| `PING` | — | — | `250 PONG` | — |
| `QUIT` | — | — | `221 bye` (y cierra) | — |

## 6. Códigos de estado

| Code | Significado |
|---|---|
| `220` | service ready (saludo inicial) |
| `221` | closing connection (respuesta a `QUIT`) |
| `250` | OK / datos a continuación |
| `400` | syntax / bad request |
| `401` | unauthorized (falta `AUTH`, o credenciales inválidas) |
| `404` | not found (usuario o clave de config inexistente) |
| `409` | conflict (el usuario ya existe) |
| `413` | line too long (y se cierra) |
| `501` | command not recognized |
| `507` | storage full (ya hay `USERS_MAX` usuarios) |
| `500` | internal error |

## 7. Claves de configuración (`GET` / `SET`)

Conjunto inicial (extensible):

| Key | Valores | Efecto |
|---|---|---|
| `auth-required` | `on` / `off` | si el proxy exige user/pass o acepta NO-AUTH |
| `dissectors` | `on` / `off` | habilita los disectores (flag `-N`; sniffer 2da entrega) |
| `io-buffer` | entero (bytes) | tamaño del buffer de I/O del relay |

## 8. Ejemplo de sesión

```
S: 220 socks5d management 1.0
C: PING
S: 250 PONG
C: ADD-USER pablito pass1234
S: 401 authentication required
C: AUTH admin admin
S: 250 OK
C: ADD-USER pablito pass1234
S: 250 OK
C: LIST-USERS
S: 250 2
S: juan
S: pablito
C: GET-METRICS
S: 250 historic=1024 current=37 bytes=9912345 failed=2
C: SET auth-required off
S: 250 OK
C: QUIT
S: 221 bye
```

## 9. Robustez

- El parsing del servidor es **incremental** (lecturas parciales): se acumula
  hasta encontrar CRLF, respetando el límite de 1024.
- Comando no reconocido → `501`. Argumentos faltantes/sobrantes → `400`.
- Conviene un timeout de inactividad por conexión (el selector ya provee un
  timeout de iteración).

## 10. El cliente

Cliente de terminal cómodo (no `netcat`). Uso esperado:

```
client [-L <host>] [-P <port>] [-u <admin>] [-w <pass>] <subcomando> [args...]

subcomandos:  add-user <name> <pass> | del-user <name> | list-users
              metrics | get <key> | set <key> <value> | ping
```

Flujo (bloqueante): conectar → leer `220` → `AUTH` (credenciales de `-u/-w` o
variables de entorno o prompt) → si no es `250`, abortar → enviar el comando
mapeado → imprimir la respuesta → `QUIT`. Sin subcomando, modo interactivo
(REPL) opcional.
