#ifndef CMAC_H
#define CMAC_H

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
#define CMAC_OK             0   // Valor de éxito
#define CMAC_ERR            1   // Error génerico
#define CMAC_ALG_ERR        2   // Error al asignar implementación de  algoritmo
#define CMAC_CTX_ERR        3   // Error al asignar contexto
#define CMAC_INT_ERR        4   // Error en mac init
#define CMAC_UPD_ERR        5   // Error en mac update
#define CMAC_FIN_ERR        6   // Error en mac final
#define CMAC_KEY_ERR        7   // Error al generar la llave
#define CMAC_LEN_ERR        8   // Error en el tamaño de la llave
#define CMAC_MOD_ERR        9   // Error al asignar un modo

#define CMAC_MOD_AES128     0
#define CMAC_MOD_AES192     1
#define CMAC_MOD_AES256     2

#define CMAC_AES_MAX_SIZE   16

int cmac_keygen(unsigned char* key, const unsigned mode);
int cmac_compute(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, const unsigned int mode, unsigned char* out, size_t *out_len);
int cmac_verify(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len,const unsigned int mode, const unsigned char* out, size_t out_len);

#endif
