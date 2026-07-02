#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <check.h>

#include "access_log.h"

/* Destino del log para cada test: un archivo temporal en memoria/disco que se
 * autodestruye al cerrarse. Escribimos con access_log_record y despues lo
 * releemos para verificar el formato. */
static FILE *log_out;

static void
setup(void) {
    log_out = tmpfile();
    ck_assert_ptr_nonnull(log_out);
    access_log_init(log_out);
}

static void
teardown(void) {
    if (log_out != NULL) {
        fclose(log_out);
        log_out = NULL;
    }
}

/* sockaddr_in de prueba: 10.0.0.5:54321 */
static struct sockaddr_in
make_client(void) {
    struct sockaddr_in c;
    memset(&c, 0, sizeof(c));
    c.sin_family = AF_INET;
    c.sin_port   = htons(54321);
    inet_pton(AF_INET, "10.0.0.5", &c.sin_addr);
    return c;
}

/* Lee la proxima linea del log (desde el inicio hay que rewind antes). */
static bool
next_line(char *out, size_t n) {
    return fgets(out, (int) n, log_out) != NULL;
}

/* Parte 'line' (la modifica) en campos por TAB/newline. Devuelve la cantidad. */
static int
split_fields(char *line, char *fields[], int max) {
    int n = 0;
    for (char *tok = strtok(line, "\t\n"); tok != NULL && n < max; tok = strtok(NULL, "\t\n")) {
        fields[n++] = tok;
    }
    return n;
}

START_TEST (test_basic_format) {
    struct sockaddr_in c = make_client();
    access_log_record("pablito", (struct sockaddr *) &c, 0x03, "example.com", 443, 0x00);

    rewind(log_out);
    char line[256];
    ck_assert(next_line(line, sizeof(line)));

    /* timestamp ISO-8601: YYYY-MM-DDTHH:MM:SSZ (chequeamos la estructura) */
    ck_assert_int_eq('-', line[4]);
    ck_assert_int_eq('-', line[7]);
    ck_assert_int_eq('T', line[10]);
    ck_assert_int_eq(':', line[13]);
    ck_assert_int_eq(':', line[16]);
    ck_assert_int_eq('Z', line[19]);

    /* campos separados por TAB y contenido esperado */
    ck_assert_ptr_nonnull(strchr(line, '\t'));
    ck_assert_ptr_nonnull(strstr(line, "pablito"));
    ck_assert_ptr_nonnull(strstr(line, "10.0.0.5:54321"));   /* cliente ip:puerto */
    ck_assert_ptr_nonnull(strstr(line, "example.com:443"));  /* destino:puerto    */
    ck_assert_ptr_nonnull(strstr(line, "0x00"));             /* REP en hex        */

    /* termina en newline */
    ck_assert_int_eq('\n', line[strlen(line) - 1]);
}
END_TEST

START_TEST (test_five_fields) {
    struct sockaddr_in c = make_client();
    access_log_record("ana", (struct sockaddr *) &c, 0x01, "1.2.3.4", 80, 0x00);

    rewind(log_out);
    char line[256];
    ck_assert(next_line(line, sizeof(line)));

    char *f[8];
    ck_assert_int_eq(5, split_fields(line, f, 8));   /* ts, user, client, dest, rep */
    ck_assert_str_eq("ana", f[1]);
    ck_assert_str_eq("1.2.3.4:80", f[3]);
}
END_TEST

START_TEST (test_null_username) {
    struct sockaddr_in c = make_client();
    access_log_record(NULL, (struct sockaddr *) &c, 0x01, "1.2.3.4", 80, 0x00);

    rewind(log_out);
    char line[256];
    ck_assert(next_line(line, sizeof(line)));

    char *f[8];
    ck_assert_int_eq(5, split_fields(line, f, 8));
    ck_assert_str_eq("-", f[1]);   /* sin auth -> usuario "-" */
}
END_TEST

START_TEST (test_null_dest) {
    struct sockaddr_in c = make_client();
    access_log_record("u", (struct sockaddr *) &c, 0x03, NULL, 8080, 0x00);

    rewind(log_out);
    char line[256];
    ck_assert(next_line(line, sizeof(line)));

    char *f[8];
    ck_assert_int_eq(5, split_fields(line, f, 8));
    ck_assert_str_eq("-:8080", f[3]);   /* destino NULL -> "-" con su puerto */
}
END_TEST

START_TEST (test_rep_hex_and_multiline) {
    struct sockaddr_in c = make_client();
    access_log_record("u", (struct sockaddr *) &c, 0x01, "d", 1, 0x05);   /* padding */
    access_log_record("u", (struct sockaddr *) &c, 0x01, "d", 1, 0xAB);   /* mayúsculas */

    rewind(log_out);
    char line[256];
    char *f[8];

    ck_assert(next_line(line, sizeof(line)));            /* primera línea */
    ck_assert_int_eq(5, split_fields(line, f, 8));
    ck_assert_str_eq("0x05", f[4]);                      /* 2 dígitos, con cero */

    ck_assert(next_line(line, sizeof(line)));            /* segunda línea */
    ck_assert_int_eq(5, split_fields(line, f, 8));
    ck_assert_str_eq("0xAB", f[4]);                      /* hex en mayúsculas */

    ck_assert(!next_line(line, sizeof(line)));           /* no hay una tercera */
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("access_log");
    TCase *tc = tcase_create("access_log");

    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_basic_format);
    tcase_add_test(tc, test_five_fields);
    tcase_add_test(tc, test_null_username);
    tcase_add_test(tc, test_null_dest);
    tcase_add_test(tc, test_rep_hex_and_multiline);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    SRunner *sr = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
