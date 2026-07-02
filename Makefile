include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/server
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client

all: client server
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/shared
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

# --- Tests unitarios (framework: check) ---
CHECK_LIBS=$(shell pkg-config --libs check)
TEST_USERS=$(OUTPUT_FOLDER)/users_test
TEST_ACCESS_LOG=$(OUTPUT_FOLDER)/access_log_test

# users_test incluye users.c directamente (caja blanca: resetea 'count'),
# por eso se compila SOLO el .c del test ($<); NO se linkea users.c aparte.
$(TEST_USERS): test/users_test.c src/server/users.c src/server/users.h
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server $< -o $@ $(CHECK_LIBS)

# access_log_test usa la API publica (caja negra): linkea access_log.c + deps.
$(TEST_ACCESS_LOG): test/access_log_test.c src/server/access_log.c src/shared/netutils.c src/shared/buffer.c
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server $^ -o $@ $(CHECK_LIBS)

test: $(TEST_USERS) $(TEST_ACCESS_LOG)
	$(TEST_USERS)
	$(TEST_ACCESS_LOG)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client clean test
