#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "users.c"

static void
setup(void) {
    count = 0;
}

START_TEST (test_add_login) {
    ck_assert_int_eq(USERS_OK, users_add("ana", "1234"));
    ck_assert(users_login("ana", "1234"));         /* credenciales correctas */
    ck_assert(!users_login("ana", "malpass"));     /* pass incorrecto        */
    ck_assert(!users_login("nadie", "x"));         /* usuario inexistente    */
    ck_assert_uint_eq(1, users_count());
}
END_TEST

START_TEST (test_add_validation) {
    ck_assert_int_eq(USERS_BADREQ, users_add("", "x"));    /* nombre vacio */
    ck_assert_int_eq(USERS_BADREQ, users_add("x", ""));    /* pass vacio   */
    ck_assert_int_eq(USERS_BADREQ, users_add(NULL, "x"));  /* name NULL    */
    ck_assert_int_eq(USERS_BADREQ, users_add("x", NULL));  /* pass NULL    */

    /* nombre demasiado largo: USERS_NAME_MAX + 1 caracteres */
    char big[USERS_NAME_MAX + 2];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ck_assert_int_eq(USERS_BADREQ, users_add(big, "x"));

    ck_assert_uint_eq(0, users_count());                   /* nada de alta */
}
END_TEST

START_TEST (test_add_duplicate) {
    ck_assert_int_eq(USERS_OK,  users_add("bob", "p"));
    ck_assert_int_eq(USERS_DUP, users_add("bob", "otra")); /* mismo nombre */
    ck_assert_uint_eq(1, users_count());
}
END_TEST

START_TEST (test_add_full) {
    char name[16];
    for (int i = 0; i < USERS_MAX; i++) {
        snprintf(name, sizeof(name), "user%d", i);
        ck_assert_int_eq(USERS_OK, users_add(name, "p"));
    }
    ck_assert_uint_eq(USERS_MAX, users_count());
    ck_assert_int_eq(USERS_FULL, users_add("unomas", "p")); /* lleno */
}
END_TEST

START_TEST (test_del) {
    ck_assert_int_eq(USERS_OK, users_add("carla", "p"));
    ck_assert_int_eq(USERS_OK, users_add("dario", "p"));

    ck_assert_int_eq(USERS_OK, users_del("carla"));
    ck_assert(!users_login("carla", "p"));         /* ya no puede loguear */
    ck_assert(users_login("dario", "p"));          /* el otro sobrevive   */
    ck_assert_uint_eq(1, users_count());

    ck_assert_int_eq(USERS_NOTFOUND, users_del("fantasma"));
}
END_TEST

START_TEST (test_list) {
    ck_assert_int_eq(USERS_OK, users_add("uno", "p"));
    ck_assert_int_eq(USERS_OK, users_add("dos", "p"));
    ck_assert_int_eq(USERS_OK, users_add("tres", "p"));

    struct user_view view[USERS_MAX];
    size_t n = users_list(view, USERS_MAX);
    ck_assert_uint_eq(3, n);
    for (size_t i = 0; i < n; i++) {
        ck_assert_ptr_nonnull(view[i].name);
    }

    /* respeta el tope 'max' cuando es menor que la cantidad */
    n = users_list(view, 2);
    ck_assert_uint_eq(2, n);
}
END_TEST

START_TEST (test_init) {
    struct socks5args args;
    memset(&args, 0, sizeof(args));   /* deja los name en NULL (centinela) */
    args.users[0].name = "eze";
    args.users[0].pass = "clave1";
    args.users[1].name = "flor";
    args.users[1].pass = "clave2";

    users_init(&args);

    ck_assert_uint_eq(2, users_count());
    ck_assert(users_login("eze", "clave1"));
    ck_assert(users_login("flor", "clave2"));
    ck_assert(!users_login("eze", "clave2"));
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("users");
    TCase *tc = tcase_create("users");

    tcase_add_checked_fixture(tc, setup, NULL);
    tcase_add_test(tc, test_add_login);
    tcase_add_test(tc, test_add_validation);
    tcase_add_test(tc, test_add_duplicate);
    tcase_add_test(tc, test_add_full);
    tcase_add_test(tc, test_del);
    tcase_add_test(tc, test_list);
    tcase_add_test(tc, test_init);
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
