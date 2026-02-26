#ifndef AUTH_H
#define AUTH_H
#include "common.h"

int auth_init(void);
void auth_cleanup(void);
int auth_register(const char *username, const char *password);
int auth_login(const char *username, const char *password, Session *session);
void auth_logout(Session *session);
int auth_is_session_valid(const Session *session);
int auth_change_password(int user_id, const char *old_password, const char *new_password);
int auth_validate_password_strength(const char *password);
int auth_validate_username(const char *username);
int auth_change_master_password(Session *session, const char *old_password, const char *new_password);

#endif
/* AUTH_H */