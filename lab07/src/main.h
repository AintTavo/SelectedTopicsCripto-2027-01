#ifndef MAIN_H
#define MAIN_H


// Librerías estándar
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

// librerías externas
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

// Liberías propias
#include "kmac/kmac.h"
#include "hmac/hmac.h"
#include "cmac/cmac.h"

#define LAB07_OK            0   // Valor de éxito
#define LAB07_ERR           1   // Error génerico
#define LAB07_ALG_ERR       2   // Error al asignar implementación de  algoritmo
#define LAB07_CTX_ERR       3   // Error al asignar contexto
#define LAB07_INT_ERR       4   // Error en mac init
#define LAB07_UPD_ERR       5   // Error en mac update
#define LAB07_FIN_ERR       6   // Error en mac final

#endif

