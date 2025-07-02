/**
 * C interface for the Protect.php FFI library.
 *
 * This header provides the C interface for the CipherStash Client SDK,
 * enabling integration through PHP's Foreign Function Interface (FFI).
 * All functions declared here are exposed by the underlying Rust library.
 */

#include <stdint.h>

typedef struct Client Client;
Client* new_client(const char* config_json, char** error_out);
char* encrypt(const Client* client, const char* plaintext, const char* column, const char* table, const char* context_json, char** error_out);
char* decrypt(const Client* client, const char* ciphertext, const char* context_json, char** error_out);
char* encrypt_bulk(const Client* client, const char* items_json, char** error_out);
char* decrypt_bulk(const Client* client, const char* items_json, char** error_out);
char* create_search_terms(const Client* client, const char* terms_json, char** error_out);
void free_client(Client* client);
void free_string(char* s);
