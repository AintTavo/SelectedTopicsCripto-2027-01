#include "kmac.h"


int kmac_keygen(){
    return KMAC_OK;
}

int kmac_compute(
    const unsigned char* key, size_t key_len, 
    const unsigned char* data, size_t data_len, 
    const char *custom_str,
    unsigned char* out, size_t out_len
){
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    int idx = 0;

    // Asignación de implmentación de MAC
    mac = EVP_MAC_fetch(NULL, "KMAC-128", NULL);
    if (!mac) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return KMAC_ALG_ERR;    // Error al adjuntar el algoritmo HMAC
    }
    
    // Crear el contexto
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return KMAC_CTX_ERR;  // Error al asignar el contexto
    } 

    if (custom_str) {
        params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CUSTOM, (char*)custom_str, 0);
    }

    params[idx++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &out_len);
    params[idx] = OSSL_PARAM_construct_end();
    
    if ( !EVP_MAC_init(ctx, key, key_len, params) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return KMAC_INT_ERR;
    }
    if ( !EVP_MAC_update(ctx, data, data_len) ) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return KMAC_UPD_ERR;
    }
    if ( !EVP_MAC_final(ctx, out, &out_len, out_len) )  {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return KMAC_FIN_ERR;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return KMAC_OK;
};

int kmac_verify() {
    return KMAC_OK;
}