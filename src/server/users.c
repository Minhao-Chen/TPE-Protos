#include <stdio.h>
#include <string.h>

#include "users.h"

struct user {
    char name[USERS_NAME_MAX + 1];
    char pass[USERS_PASS_MAX + 1];
};
static struct user users[USERS_MAX];
static size_t count = 0;

static int find_user(const char *name) {
    for (int i = 0; i < count; i++) {
        if (strcmp(users[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

void
users_init(const struct socks5args *args){
    int i = 0;
    while (i < USERS_MAX && args->users[i].name != NULL) {
        users_add(args->users[i].name, args->users[i].pass);
        i++;
    }
}

bool
users_login(const char *name, const char *pass){
    int index = find_user(name);
    if (index != -1 && strcmp(users[index].pass, pass) == 0) {
        return true;
    }
    return false;
}

enum users_result
users_add(const char *name, const char *pass){
    if (name == NULL || pass == NULL) {
        return USERS_BADREQ;
    }
    size_t len_name = strlen(name);
    size_t len_pass = strlen(pass);
    if (len_name == 0 || len_pass == 0 || len_name > USERS_NAME_MAX || len_pass > USERS_PASS_MAX) {
        return USERS_BADREQ;
    }
    if (find_user(name) != -1) {
        return USERS_DUP;
    }
    if (count >= USERS_MAX) {
        return USERS_FULL;
    }
    strcpy(users[count].name, name);
    strcpy(users[count].pass, pass);
    count++;
    return USERS_OK;
}

enum users_result
users_del(const char *name){
    int index = find_user(name);
    if (index == -1) {
        return USERS_NOTFOUND;
    }
    users[index] = users[count - 1];
    count--;
    return USERS_OK;
}

size_t
users_list(struct user_view *out, size_t max){
    size_t i;
    for (i = 0; i < count && i < max; i++) {
        out[i].name = users[i].name;
    }
    return i;
}

size_t
users_count(void){
    return count;
}