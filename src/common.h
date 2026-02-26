#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <time.h>

#define MAX_USERNAME_LENGTH 50
#define MAX_SERVICE_NAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 256
#define HASH_LENGTH 65          
#define SALT_LENGTH 33          
#define MAX_ENCRYPTED_LENGTH 512


#define SUCCESS 0
#define ERROR_INVALID_PARAMS -1
#define ERROR_USER_NOT_FOUND -2
#define ERROR_USER_EXISTS -3
#define ERROR_AUTH_FAILED -4
#define ERROR_DB -5
#define ERROR_CRYPTO -6
#define ERROR_MEMORY -7


typedef struct {
    int user_id;                        
    char username[MAX_USERNAME_LENGTH];
    char password_hash[HASH_LENGTH];  
    char salt[SALT_LENGTH];             
    time_t created_at;                 
    time_t last_login;                
} User;

typedef struct {
    int entry_id;                          
    int user_id;                           
    char service_name[MAX_ENCRYPTED_LENGTH];  
    char service_iv[33];                       
    char username[MAX_ENCRYPTED_LENGTH];       
    char username_iv[33];                      
    char encrypted_password[MAX_ENCRYPTED_LENGTH]; 
    char iv[33];                           
    time_t created_at;                     
    time_t modified_at;                     
} PasswordEntry;


typedef struct {
    int user_id;
    char username[MAX_USERNAME_LENGTH];
    uint8_t master_key[32];  // Clé dérivée du mot de passe maître (pour chiffrement)
    int is_authenticated;
    time_t session_start;
} Session;

#endif /* COMMON_H */