#include "cmac.h"

int cmac_keygen(unsigned char* key, const unsigned mode) {
    size_t key_len = 0;

    switch (mode) {
        case CMAC_MOD_AES128:
            key_len = 16;
            break;
        case CMAC_MOD_AES192:
            key_len = 24;
            break;
        case CMAC_MOD_AES256:
            key_len = 32;
            break;
        default:
            return CMAC_MOD_ERR;
    }

    if (RAND_priv_bytes(key, key_len) != 1) {
        return CMAC_KEY_ERR;
    }

    return CMAC_OK;
}

int cmac_compute(
    const unsigned char* key, size_t key_len,
    const unsigned char* data, size_t data_len,
    const unsigned int mode,
    unsigned char* out, size_t *out_len
) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    char *cipher_name = NULL;
    size_t expected_key_len = 0;

    switch (mode) {
        case CMAC_MOD_AES128:
            cipher_name = (char*)"AES-128-CBC";
            expected_key_len = 16;
            break;
        case CMAC_MOD_AES192:
            cipher_name = (char*)"AES-192-CBC";
            expected_key_len = 24;
            break;
        case CMAC_MOD_AES256:
            cipher_name = (char*)"AES-256-CBC";
            expected_key_len = 32;
            break;
        default:
            return CMAC_MOD_ERR;
    }

    if (key_len != expected_key_len) {
        return CMAC_LEN_ERR;
    }

    // Asignación de implementación de MAC
    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) {
        return CMAC_ALG_ERR;    // Error al adjuntar el algoritmo CMAC
    }

    // Crear el contexto
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return CMAC_CTX_ERR;    // Error al asignar el contexto
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, key, key_len, params)) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_INT_ERR;
    }
    if (!EVP_MAC_update(ctx, data, data_len)) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_UPD_ERR;
    }

    size_t buf_cap = (*out_len > 0) ? *out_len : CMAC_AES_MAX_SIZE;
    if (!EVP_MAC_final(ctx, out, out_len, buf_cap)) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return CMAC_FIN_ERR;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return CMAC_OK;
}

int cmac_verify(
    const unsigned char* key, size_t key_len,
    const unsigned char* data, size_t data_len,
    const unsigned int mode,
    const unsigned char* out, size_t out_len
) {
    unsigned char tmp_out[CMAC_AES_MAX_SIZE];
    size_t tmp_out_len = CMAC_AES_MAX_SIZE;

    int out_cmac = cmac_compute(key, key_len, data, data_len, mode, tmp_out, &tmp_out_len);
    if (out_cmac != CMAC_OK) return out_cmac;

    if (out_len != tmp_out_len) return CMAC_ERR;

    if (CRYPTO_memcmp(out, tmp_out, out_len) != 0) return CMAC_ERR;
    return CMAC_OK;
}
