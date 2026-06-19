COMPILER=gcc

# -std=c11            : exigido por la consigna (ISO/IEC 9899:2011)
# -D_POSIX_C_SOURCE   : habilita APIs POSIX (pthread, getaddrinfo, sigaction...)
# -D_DEFAULT_SOURCE   : sockaddr_storage, INET6_ADDRSTRLEN, etc.
# -I./src/shared      : headers del framework compartido (selector, buffer, ...)
COMPILER_FLAGS=-Wall -pedantic -g -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I./src/shared

# El selector usa pthreads (resolución de nombres en hilo aparte)
LD_FLAGS=-pthread
