#include "kmac.h"

int kmac_keygen(unsigned char* key, const unsigned int mode, size_t key_len){
    int min_len = ( mode == KMAC_MOD_128 ) ? 16 : 32;
    if (key_len < min_len) return KMAC_LEN_ERR;
    if ( RAND_priv_bytes(key, key_len) != 1 ) return KMAC_KEY_ERR; 
    return KMAC_OK;
}

int kmac_compute(
    const unsigned char* key, size_t key_len, 
    const unsigned char* data, size_t data_len, 
    const char *custom_str,
    const unsigned int mode,
    unsigned char* out, size_t out_len
){
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    int idx = 0;

    // Asignación de implmentación de MAC
    switch (mode) {
        case KMAC_MOD_128 : 
            mac = EVP_MAC_fetch(NULL, "KMAC-128", NULL);
            break;
        case KMAC_MOD_256 : 
            mac = EVP_MAC_fetch(NULL, "KMAC-256", NULL);
            break;
        default: return KMAC_ALG_ERR;
    }
    
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

int kmac_verify(
    const unsigned char* key, size_t key_len,
    const unsigned char* data, size_t data_len,
    const char *custom_str,
    const unsigned int mode,
    const unsigned char* out, size_t out_len
) {
    unsigned char* tmp_out;
    
    int out_kmac = kmac_compute(key, key_len, data, data_len, custom_str, mode, tmp_out, out_len);
    if ( out_kmac != KMAC_OK ) return out_kmac;
    
    if ( !CRYPTO_memcmp(out, tmp_out, out_len) ) return KMAC_ERR;
    return KMAC_OK;
}