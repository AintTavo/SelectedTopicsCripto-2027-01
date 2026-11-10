#include "hmac.h"

int hmac_compute(
    const unsigned char* key, 
    size_t key_len, 
    const unsigned char* data,
    size_t data_len,
    unsigned char* out,
    size_t *out_len
) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    // Asignación de implmentación de MAC
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return HMAC_ALG_ERR;    // Error al adjuntar el algoritmo HMAC
    }
    
    // Crear el contexto
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return HMAC_CTX_ERR;  // Error al asignar el contexto
    } 

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if ( !EVP_MAC_init(ctx, key, key_len, params) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return HMAC_INT_ERR;
    }
    if ( !EVP_MAC_update(ctx, data, data_len) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return HMAC_UPD_ERR;
    }
    if ( !EVP_MAC_final(ctx, out, out_len, *out_len) )  {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return HMAC_FIN_ERR;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return HMAC_OK;
};