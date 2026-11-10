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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

// Definiciones 
#define HMAC_OK             0   // Valor de éxito
#define HMAC_ERR            1   // Error génerico
#define HMAC_ALG_ERR        2   // Error al asignar implementación de  algoritmo
#define HMAC_CTX_ERR        3   // Error al asignar contexto
#define HMAC_INT_ERR        4   // Error en mac init
#define HMAC_UPD_ERR        5   // Error en mac update
#define HMAC_FIN_ERR        6   // Error en mac final
#define HMAC_KEY_ERR        7   // Error al generar llave
#define HMAC_LEN_ERR        8   // Error del tamaño de la llave a generar
#define HMAC_MOD_ERR        9   // Error al escoger modo

#define HMAC_MOD_256        0   // Modo de HMAC con SHA-256
#define HMAC_MOD_512        1   // Modo de HMAC con SHA-512

int hmac_keygen(unsigned char* key, const unsigned mode, size_t key_len);
int hmac_compute(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, const unsigned int mode, unsigned char* out, size_t *out_len);
int hmac_verify(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, const unsigned int mode, const unsigned char* out, size_t out_len);

#endif