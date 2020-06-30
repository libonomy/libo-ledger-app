#include <stdint.h>
#include <stdbool.h>

#define PUBLIC_KEY_SIZE 32

bool hex_to_bytes(char* hex, uint8_t *buffer);

void int64_to_hex_proper_endian(int64_t number, char hex[17]);

void uint64_to_hex_proper_endian(uint64_t number, char hex[17]);

void extract_public_key(cx_ecfp_public_key_t publicKey, uint8_t *buffer);

void buffer_to_hex(uint8_t *buffer, char *hex, size_t buffer_length);