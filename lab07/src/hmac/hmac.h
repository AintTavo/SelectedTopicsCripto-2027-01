#ifndef HMAC_H
#define HMAC_H

// librerías estándar
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

// Librerías externas 
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

// Definiciones 
#define HMAC_OK            0   // Valor de éxito
#define HMAC_ERR           1   // Error génerico
#define HMAC_ALG_ERR       2   // Error al asignar implementación de  algoritmo
#define HMAC_CTX_ERR       3   // Error al asignar contexto
#define HMAC_INT_ERR       4   // Error en mac init
#define HMAC_UPD_ERR       5   // Error en mac update
#define HMAC_FIN_ERR       6   // Error en mac final

int hmac_keygen();
int hmac_compute(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* out, size_t *out_len);
int hmac_verify(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, const unsigned char* out, size_t *out_len);

#endif