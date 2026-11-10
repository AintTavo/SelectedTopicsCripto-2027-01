#ifndef KMAC_H
#define KMAC_H

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
#define KMAC_OK            0   // Valor de éxito
#define KMAC_ERR           1   // Error génerico
#define KMAC_ALG_ERR       2   // Error al asignar implementación de  algoritmo
#define KMAC_CTX_ERR       3   // Error al asignar contexto
#define KMAC_INT_ERR       4   // Error en mac init
#define KMAC_UPD_ERR       5   // Error en mac update
#define KMAC_FIN_ERR       6   // Error en mac final

int kmac_compute(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, const char *custom_str, unsigned char* out, size_t out_len);

#endif