#include "cmac.h"

int cmac_keygen() {
    return CMAC_OK;
}

int cmac_compute(
    const unsigned char* key, size_t key_len,
    const unsigned char* data, size_t data_len, 
    unsigned char* out, size_t *out_len
){
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    // Asignación de implmentación de MAC
    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_ALG_ERR;    // Error al adjuntar el algoritmo HMAC
    }
    
    // Crear el contexto
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_CTX_ERR;  // Error al asignar el contexto
    } 

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char*)"AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if ( !EVP_MAC_init(ctx, key, key_len, params) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_INT_ERR;
    }
    if ( !EVP_MAC_update(ctx, data, data_len) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_UPD_ERR;
    }
    if ( !EVP_MAC_final(ctx, out, out_len, *out_len) )  {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_FIN_ERR;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return CMAC_OK;
};

int cmac_verify(
    const unsigned char* key, size_t key_len, 
    const unsigned char* data, size_t data_len, 
    const unsigned char* out, size_t out_len
) {
    unsigned char* tmp_out;
    size_t tmp_out_len = 0;

    int out_cmac = cmac_compute(key, key_len, data, data_len, tmp_out, &tmp_out_len);
    if (out_cmac != CMAC_OK) return out_cmac;

    if ( out_len != tmp_out_len ) return CMAC_ERR;
    
    if ( !CRYPTO_memcmp(out, tmp_out, out_len) ) return CMAC_ERR;
    return CMAC_OK;
}