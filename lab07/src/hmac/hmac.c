#include "hmac.h"

int hmac_keygen(unsigned char* key, const unsigned mode, size_t key_len) {
    int min_len = ( mode == HMAC_MOD_256 ) ? 32 : 64;
    int max_len = ( mode == HMAC_MOD_256 ) ? 64 : 128;

    if ( key_len < min_len || key_len > max_len ) return HMAC_LEN_ERR;

    if ( RAND_priv_bytes(key, key_len) != 1 ) return HMAC_KEY_ERR;
    
    return HMAC_OK;
}

int hmac_compute(
    const unsigned char* key, size_t key_len, 
    const unsigned char* data, size_t data_len,
    const unsigned int mode,
    unsigned char* out, size_t *out_len
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

    switch (mode) {
        case HMAC_MOD_256 :
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
            break;
        case HMAC_MOD_512 :
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA512", 0);
            break;
        default : return HMAC_MOD_ERR; 
    }
    
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

int hmac_verify( 
    const unsigned char* key, size_t key_len, 
    const unsigned char* data, size_t data_len, 
    const unsigned int mode,
    const unsigned char* out, size_t out_len
) {
    unsigned char* tmp_out;
    size_t tmp_out_len = 0;

    int out_hmac = hmac_compute(key, key_len, data, data_len, mode, tmp_out, &tmp_out_len);
    if ( out_hmac != HMAC_OK ) return out_hmac; 

    if ( out_len != tmp_out_len ) return HMAC_ERR;

    if ( !CRYPTO_memcmp(out, tmp_out, out_len) ) return HMAC_ERR;
    return HMAC_OK;
}