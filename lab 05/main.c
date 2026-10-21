#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define FIPS_KEY_SIZE 3072

/* =========================================================================
 * PROTOTIPOS DE FUNCIONES (PRACTICA 5 / FIPS 186-5)
 * ========================================================================= */

/* Ejercicio 1: Generación de llaves y almacenamiento en base64 */
EVP_PKEY* rsa_key_gen(int bits);
int rsassa_generate_and_save_keys(int bits, const char *priv_file, const char *pub_file);

/* Carga de llaves desde archivos de texto en base64 / PEM */
EVP_PKEY* load_private_key_from_file(const char *filename);
EVP_PKEY* load_public_key_from_file(const char *filename);

/* Funciones base de firma y verificación RSASSA-PSS en memoria */
int rsassa_signature_pss(
    EVP_PKEY *priv_key,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char **signature,
    size_t *sig_len,
    const EVP_MD *hash_alg
);
/* Alias para compatibilidad con código previo */
int rsassa_signature_pass(
    EVP_PKEY *priv_key,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char **signature,
    size_t *sig_len,
    const EVP_MD *hash_alg
);
bool rsassa_verify_pss(
    EVP_PKEY *pub_key,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char *signature,
    size_t sig_len,
    const EVP_MD *hash_alg
);

/* Ejercicio 2: Firma de archivo recibiendo archivo de clave privada y archivo a firmar */
unsigned char* rsassa_sign_file(
    const char *priv_key_file,
    const char *msg_file,
    size_t *sig_len,
    const EVP_MD *hash_alg
);

/* Ejercicio 3: Verificación recibiendo archivo de clave pública, archivo con mensaje m y firma */
bool rsassa_verify_file(
    const char *pub_key_file,
    const char *msg_file,
    const unsigned char *signature,
    size_t sig_len,
    const EVP_MD *hash_alg
);
bool rsassa_verify_from_files(
    const char *pub_key_file,
    const char *msg_file,
    const char *sig_file,
    const EVP_MD *hash_alg
);

/* Utilidades auxiliares (Base64, Hex, I/O) */
char* base64_encode(const unsigned char *input, size_t length);
unsigned char* base64_decode(const char *input, size_t *out_len);
int save_signature_to_file(const char *filename, const unsigned char *sig, size_t sig_len);
unsigned char* load_signature_from_file(const char *filename, size_t *sig_len);
void print_hex(const unsigned char *data, size_t len);
const EVP_MD* get_hash_algorithm_by_choice(int choice);
const char* get_hash_name(const EVP_MD *md);
void clear_input_buffer(void);
void run_automated_test_suite(void);
void show_menu(void);
void interactive_cli(void);

/* =========================================================================
 * IMPLEMENTACIÓN DE UTILIDADES BASE64 Y FORMATO
 * ========================================================================= */

char* base64_encode(const unsigned char *input, size_t length) {
    if (!input || length == 0) return NULL;
    BIO *bmem = NULL, *b64 = NULL;
    BUF_MEM *bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return NULL;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    if (!bmem) {
        BIO_free(b64);
        return NULL;
    }
    b64 = BIO_push(b64, bmem);

    if (BIO_write(b64, input, (int)length) <= 0 || BIO_flush(b64) <= 0) {
        BIO_free_all(b64);
        return NULL;
    }
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    if (buff) {
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = '\0';
    }
    BIO_free_all(b64);
    return buff;
}

unsigned char* base64_decode(const char *input, size_t *out_len) {
    if (!input || !out_len) return NULL;
    *out_len = 0;

    size_t in_len = strlen(input);
    if (in_len == 0) return NULL;

    /* Filtrar espacios en blanco y saltos de línea */
    char *clean = (char *)malloc(in_len + 1);
    if (!clean) return NULL;
    size_t clean_len = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (!isspace((unsigned char)input[i])) {
            clean[clean_len++] = input[i];
        }
    }
    clean[clean_len] = '\0';

    if (clean_len == 0) {
        free(clean);
        return NULL;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        free(clean);
        return NULL;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new_mem_buf(clean, (int)clean_len);
    if (!bmem) {
        BIO_free(b64);
        free(clean);
        return NULL;
    }
    bmem = BIO_push(b64, bmem);

    unsigned char *buffer = (unsigned char *)malloc(clean_len);
    if (!buffer) {
        BIO_free_all(bmem);
        free(clean);
        return NULL;
    }

    int decoded_size = BIO_read(bmem, buffer, (int)clean_len);
    BIO_free_all(bmem);
    free(clean);

    if (decoded_size <= 0) {
        free(buffer);
        *out_len = 0;
        return NULL;
    }
    *out_len = (size_t)decoded_size;
    return buffer;
}

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && (i + 1) < len) {
            printf("\n       ");
        }
    }
    printf("\n");
}

void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

const EVP_MD* get_hash_algorithm_by_choice(int choice) {
    switch (choice) {
        case 2:  return EVP_sha384();
        case 3:  return EVP_sha512();
        case 4:  return EVP_sha3_256();
        case 5:  return EVP_sha3_512();
        case 1:
        default: return EVP_sha256();
    }
}

const char* get_hash_name(const EVP_MD *md) {
    if (md == EVP_sha256())   return "SHA2-256";
    if (md == EVP_sha384())   return "SHA2-384";
    if (md == EVP_sha512())   return "SHA2-512";
    if (md == EVP_sha3_256()) return "SHA3-256";
    if (md == EVP_sha3_512()) return "SHA3-512";
    return "DESCONOCIDO";
}

/* Guardar firma en archivo como texto Base64 legible */
int save_signature_to_file(const char *filename, const unsigned char *sig, size_t sig_len) {
    if (!filename || !sig || sig_len == 0) return 0;
    FILE *f = fopen(filename, "w");
    if (!f) return 0;

    char *b64 = base64_encode(sig, sig_len);
    if (!b64) {
        fclose(f);
        return 0;
    }
    fprintf(f, "%s\n", b64);
    free(b64);
    fclose(f);
    return 1;
}

/* Cargar firma desde archivo (soporta formato texto Base64 o binario) */
unsigned char* load_signature_from_file(const char *filename, size_t *sig_len) {
    if (!filename || !sig_len) return NULL;
    *sig_len = 0;

    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fclose(f);
        return NULL;
    }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, sz, f);
    fclose(f);
    buf[read_bytes] = '\0';

    /* Intentar decodificar como Base64 */
    unsigned char *decoded = base64_decode(buf, sig_len);
    if (decoded && *sig_len > 0) {
        free(buf);
        return decoded;
    }

    /* Si no era Base64, retornar como datos binarios directos */
    *sig_len = read_bytes;
    return (unsigned char *)buf;
}

/* =========================================================================
 * EJERCICIO 1: GENERACIÓN Y ALMACENAMIENTO DE LLAVES (FIPS 186-5)
 * ========================================================================= */

/* Generación de contexto y llaves RSA con longitud acorde a FIPS 186-5 */
EVP_PKEY* rsa_key_gen(int bits) {
    if (bits <= 0) bits = FIPS_KEY_SIZE;
    EVP_PKEY *pkey = NULL;

    /* Contexto para la generación de llaves RSA */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err_key;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0) goto err_key;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto err_key;

err_key:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Guarda llave privada y llave pública en archivos de texto separados usando Base64 (formato PEM estándar)
 */
int rsassa_generate_and_save_keys(int bits, const char *priv_file, const char *pub_file) {
    if (!priv_file || !pub_file) return 0;
    EVP_PKEY *pkey = rsa_key_gen(bits);
    if (!pkey) return 0;

    /* Guardar clave privada en texto base64 */
    FILE *fpriv = fopen(priv_file, "w");
    if (!fpriv) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    if (PEM_write_PrivateKey(fpriv, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        fclose(fpriv);
        EVP_PKEY_free(pkey);
        return 0;
    }
    fclose(fpriv);

    /* Guardar clave pública en texto base64 */
    FILE *fpub = fopen(pub_file, "w");
    if (!fpub) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    if (PEM_write_PUBKEY(fpub, pkey) <= 0) {
        fclose(fpub);
        EVP_PKEY_free(pkey);
        return 0;
    }
    fclose(fpub);

    EVP_PKEY_free(pkey);
    return 1;
}

/* Carga clave privada desde archivo de texto en base64 / PEM */
EVP_PKEY* load_private_key_from_file(const char *filename) {
    if (!filename) return NULL;
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (pkey) {
        fclose(f);
        return pkey;
    }

    /* Fallback: decodificación Base64 manual a DER */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > 0) {
        char *buf = (char *)malloc(sz + 1);
        if (buf) {
            size_t r = fread(buf, 1, sz, f);
            buf[r] = '\0';
            size_t der_len = 0;
            unsigned char *der = base64_decode(buf, &der_len);
            if (der) {
                const unsigned char *p = der;
                pkey = d2i_AutoPrivateKey(NULL, &p, (long)der_len);
                free(der);
            }
            free(buf);
        }
    }
    fclose(f);
    return pkey;
}

/* Carga clave pública desde archivo de texto en base64 / PEM */
EVP_PKEY* load_public_key_from_file(const char *filename) {
    if (!filename) return NULL;
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    if (pkey) {
        fclose(f);
        return pkey;
    }

    /* Fallback: decodificación Base64 manual a DER */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > 0) {
        char *buf = (char *)malloc(sz + 1);
        if (buf) {
            size_t r = fread(buf, 1, sz, f);
            buf[r] = '\0';
            size_t der_len = 0;
            unsigned char *der = base64_decode(buf, &der_len);
            if (der) {
                const unsigned char *p = der;
                pkey = d2i_PUBKEY(NULL, &p, (long)der_len);
                free(der);
            }
            free(buf);
        }
    }
    fclose(f);
    return pkey;
}

/* =========================================================================
 * IMPLEMENTACIÓN BASE RSASSA-PSS (NIST FIPS 186-5)
 * ========================================================================= */

int rsassa_signature_pss(
    EVP_PKEY *priv_key,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char **signature,
    size_t *sig_len,
    const EVP_MD *hash_alg
) {
    if (!priv_key || !msg || !signature || !sig_len || !hash_alg) return 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int resultado = 0;

    if (!mdctx) return 0;

    /* Inicialización de firma inyectando función hash */
    if (EVP_DigestSignInit(mdctx, &pctx, hash_alg, NULL, priv_key) <= 0) goto err_sig;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto err_sig;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, hash_alg) <= 0) goto err_sig;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto err_sig;
    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) <= 0) goto err_sig;
    if (EVP_DigestSignFinal(mdctx, NULL, sig_len) <= 0) goto err_sig;

    *signature = (unsigned char *)OPENSSL_malloc(*sig_len);
    if (!*signature) goto err_sig;

    if (EVP_DigestSignFinal(mdctx, *signature, sig_len) <= 0) {
        OPENSSL_free(*signature);
        *signature = NULL;
        goto err_sig;
    }

    resultado = 1;
err_sig:
    EVP_MD_CTX_free(mdctx);
    return resultado;
}

/* Función alias para compatibilidad */
int rsassa_signature_pass(
    EVP_PKEY *priv_key,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char **signature,
    size_t *sig_len,
    const EVP_MD *hash_alg
) {
    return rsassa_signature_pss(priv_key, msg, msg_len, signature, sig_len, hash_alg);
}

bool rsassa_verify_pss(
    EVP_PKEY *pub_key,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char *signature,
    size_t sig_len,
    const EVP_MD *hash_alg
) {
    if (!pub_key || !msg || !signature || sig_len == 0 || !hash_alg) return false;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool validation = false;

    if (!mdctx) return false;
    if (EVP_DigestVerifyInit(mdctx, &pctx, hash_alg, NULL, pub_key) <= 0) goto err_ver;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto err_ver;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, hash_alg) <= 0) goto err_ver;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto err_ver;
    if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) <= 0) goto err_ver;

    if (EVP_DigestVerifyFinal(mdctx, signature, sig_len) == 1) {
        validation = true;
    }

err_ver:
    EVP_MD_CTX_free(mdctx);
    return validation;
}

/* =========================================================================
 * EJERCICIO 2: GENERACIÓN DE FIRMA DESDE ARCHIVO (FIPS 186-5)
 * ========================================================================= */

/*
 * Implementa la función para generar la firma con RSASSA-PSS:
 * Recibe el nombre del archivo con la clave privada d y el nombre del archivo a firmar.
 * Retorna la firma (puntero a buffer dinámico asignado).
 */
unsigned char* rsassa_sign_file(
    const char *priv_key_file,
    const char *msg_file,
    size_t *sig_len,
    const EVP_MD *hash_alg
) {
    if (!priv_key_file || !msg_file || !sig_len || !hash_alg) return NULL;
    *sig_len = 0;

    /* Cargar clave privada */
    EVP_PKEY *priv_key = load_private_key_from_file(priv_key_file);
    if (!priv_key) {
        fprintf(stderr, "[-] Error: No se pudo cargar la clave privada desde '%s'\n", priv_key_file);
        return NULL;
    }

    /* Abrir archivo de mensaje/documento */
    FILE *fmsg = fopen(msg_file, "rb");
    if (!fmsg) {
        fprintf(stderr, "[-] Error: No se pudo abrir el archivo de mensaje '%s'\n", msg_file);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *signature = NULL;

    if (!mdctx) goto cleanup;

    /* Inicializar firma con RSASSA-PSS según FIPS 186-5 */
    if (EVP_DigestSignInit(mdctx, &pctx, hash_alg, NULL, priv_key) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, hash_alg) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto cleanup;

    /* Procesar archivo por bloques */
    unsigned char buffer[8192];
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fmsg)) > 0) {
        if (EVP_DigestSignUpdate(mdctx, buffer, bytes_read) <= 0) goto cleanup;
    }

    if (ferror(fmsg)) goto cleanup;

    /* Obtener longitud de firma y firmar */
    if (EVP_DigestSignFinal(mdctx, NULL, sig_len) <= 0) goto cleanup;
    signature = (unsigned char *)OPENSSL_malloc(*sig_len);
    if (!signature) goto cleanup;

    if (EVP_DigestSignFinal(mdctx, signature, sig_len) <= 0) {
        OPENSSL_free(signature);
        signature = NULL;
        *sig_len = 0;
    }

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (fmsg) fclose(fmsg);
    if (priv_key) EVP_PKEY_free(priv_key);
    return signature;
}

/* =========================================================================
 * EJERCICIO 3: VERIFICACIÓN DE FIRMA (FIPS 186-5)
 * ========================================================================= */

/*
 * Implementa la función para verificar la firma con RSASSA-PSS:
 * Lee el archivo de texto de la clave pública, el nombre del archivo del mensaje m,
 * y la firma.
 * Retorna un valor booleano: true si la firma es válida, false si es inválida.
 */
bool rsassa_verify_file(
    const char *pub_key_file,
    const char *msg_file,
    const unsigned char *signature,
    size_t sig_len,
    const EVP_MD *hash_alg
) {
    if (!pub_key_file || !msg_file || !signature || sig_len == 0 || !hash_alg) {
        return false;
    }

    /* Cargar clave pública desde archivo */
    EVP_PKEY *pub_key = load_public_key_from_file(pub_key_file);
    if (!pub_key) {
        fprintf(stderr, "[-] Error: No se pudo cargar la clave publica desde '%s'\n", pub_key_file);
        return false;
    }

    /* Abrir archivo de mensaje m */
    FILE *fmsg = fopen(msg_file, "rb");
    if (!fmsg) {
        fprintf(stderr, "[-] Error: No se pudo abrir el archivo de mensaje '%s'\n", msg_file);
        EVP_PKEY_free(pub_key);
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool valid = false;

    if (!mdctx) goto cleanup;

    /* Inicializar verificación RSASSA-PSS */
    if (EVP_DigestVerifyInit(mdctx, &pctx, hash_alg, NULL, pub_key) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, hash_alg) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) goto cleanup;

    /* Procesar archivo de mensaje m por bloques */
    unsigned char buffer[8192];
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fmsg)) > 0) {
        if (EVP_DigestVerifyUpdate(mdctx, buffer, bytes_read) <= 0) goto cleanup;
    }

    if (ferror(fmsg)) goto cleanup;

    /* Verificar firma final */
    if (EVP_DigestVerifyFinal(mdctx, signature, sig_len) == 1) {
        valid = true;
    }

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (fmsg) fclose(fmsg);
    if (pub_key) EVP_PKEY_free(pub_key);
    return valid;
}

/* Envoltura para verificar cargando la firma desde un archivo */
bool rsassa_verify_from_files(
    const char *pub_key_file,
    const char *msg_file,
    const char *sig_file,
    const EVP_MD *hash_alg
) {
    size_t sig_len = 0;
    unsigned char *sig = load_signature_from_file(sig_file, &sig_len);
    if (!sig) {
        fprintf(stderr, "[-] Error: No se pudo cargar la firma desde '%s'\n", sig_file);
        return false;
    }

    bool res = rsassa_verify_file(pub_key_file, msg_file, sig, sig_len, hash_alg);
    free(sig);
    return res;
}

/* =========================================================================
 * EJERCICIO 4: FRONTEND CLI Y PROCEDIMIENTOS INDEPENDIENTES
 * ========================================================================= */

void show_menu(void) {
    printf("\n");
    printf("======================================================================\n");
    printf("   LABORATORIO 05: RSASSA-PSS (NIST FIPS 186-5) - CRIPTOGRAFIA\n");
    printf("======================================================================\n");
    printf("  1. Generar Par de Llaves RSASSA-PSS (Guardar en Base64)\n");
    printf("  2. Generar Firma Digital RSASSA-PSS (Firmar archivo)\n");
    printf("  3. Verificar Firma Digital RSASSA-PSS (Validar autenticidad)\n");
    printf("  4. Ejecutar Suite Automatizada de Pruebas (Demo completa FIPS)\n");
    printf("  5. Salir\n");
    printf("======================================================================\n");
    printf("Seleccione una opcion [1-5]: ");
}

/* Procedimiento 1: Generación interactiva de llaves */
static void cli_procedure_keygen(void) {
    char priv_path[256] = "private_key.txt";
    char pub_path[256] = "public_key.txt";
    char line[128];
    int bits = FIPS_KEY_SIZE;

    printf("\n----------------------------------------------------------------------\n");
    printf("  PROCEDIMIENTO 1: GENERACION DE PAR DE LLAVES RSASSA-PSS\n");
    printf("----------------------------------------------------------------------\n");

    printf("Tamano del modulo RSA en bits [2048, 3072, 4096] (default %d): ", FIPS_KEY_SIZE);
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        int val = atoi(line);
        if (val >= 2048) bits = val;
        else printf("[!] Tamano menor a 2048 bits desaconsejado por FIPS 186-5. Usando %d.\n", FIPS_KEY_SIZE);
    }

    printf("Nombre de archivo para la clave privada (Base64) [default: private_key.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(priv_path, line, sizeof(priv_path) - 1);
    }

    printf("Nombre de archivo para la clave publica (Base64) [default: public_key.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(pub_path, line, sizeof(pub_path) - 1);
    }

    printf("\n[*] Generando par de llaves RSA de %d bits conforme a FIPS 186-5...\n", bits);
    if (rsassa_generate_and_save_keys(bits, priv_path, pub_path)) {
        printf("[+] Par de llaves generado exitosamente!\n");
        printf("    -> Clave privada guardada en: '%s'\n", priv_path);
        printf("    -> Clave publica guardada en: '%s'\n", pub_path);
    } else {
        printf("[-] Error durante la generacion o guardado de las llaves.\n");
    }
}

/* Procedimiento 2: Firma interactiva */
static void cli_procedure_sign(void) {
    char priv_path[256] = "private_key.txt";
    char msg_path[256] = "mensaje.txt";
    char sig_path[256] = "firma.txt";
    char line[128];
    int hash_choice = 1;

    printf("\n----------------------------------------------------------------------\n");
    printf("  PROCEDIMIENTO 2: GENERACION DE FIRMA DIGITAL RSASSA-PSS\n");
    printf("----------------------------------------------------------------------\n");

    printf("Archivo de clave privada [default: private_key.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(priv_path, line, sizeof(priv_path) - 1);
    }

    printf("Archivo del mensaje/documento a firmar [default: mensaje.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(msg_path, line, sizeof(msg_path) - 1);
    }

    /* Si no existe el archivo de mensaje, permitir crearlo rapidamente */
    FILE *test_f = fopen(msg_path, "r");
    if (!test_f) {
        printf("[!] El archivo '%s' no existe. Desea crearlo ahora con un texto? (s/n) [default: s]: ", msg_path);
        if (fgets(line, sizeof(line), stdin) && (line[0] == '\n' || line[0] == 's' || line[0] == 'S')) {
            printf("Ingrese el contenido del mensaje: ");
            char user_content[1024];
            if (fgets(user_content, sizeof(user_content), stdin)) {
                FILE *new_msg = fopen(msg_path, "wb");
                if (new_msg) {
                    fputs(user_content, new_msg);
                    fclose(new_msg);
                    printf("[+] Archivo '%s' creado exitosamente.\n", msg_path);
                }
            }
        }
    } else {
        fclose(test_f);
    }

    printf("\nSeleccione funcion Hash (SHA2 o SHA3):\n");
    printf("  1. SHA2-256 (Estandar FIPS 186-5)\n");
    printf("  2. SHA2-384\n");
    printf("  3. SHA2-512\n");
    printf("  4. SHA3-256\n");
    printf("  5. SHA3-512\n");
    printf("Seleccion [1-5] [default: 1]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        hash_choice = atoi(line);
    }
    const EVP_MD *md = get_hash_algorithm_by_choice(hash_choice);

    printf("Archivo donde guardar la firma (Base64) [default: firma.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(sig_path, line, sizeof(sig_path) - 1);
    }

    printf("\n[*] Firmando archivo '%s' con clave '%s' usando %s...\n", msg_path, priv_path, get_hash_name(md));
    size_t sig_len = 0;
    unsigned char *signature = rsassa_sign_file(priv_path, msg_path, &sig_len, md);

    if (signature && sig_len > 0) {
        printf("[+] Firma generada exitosamente! Longitud: %zu bytes (%zu bits)\n", sig_len, sig_len * 8);

        char *b64_sig = base64_encode(signature, sig_len);
        if (b64_sig) {
            printf("\n--- Firma Digital en Base64 ---\n%s\n-------------------------------\n", b64_sig);
            free(b64_sig);
        }

        printf("Firma en formato Hex:\n       ");
        print_hex(signature, sig_len);

        if (save_signature_to_file(sig_path, signature, sig_len)) {
            printf("[+] Firma guardada exitosamente en '%s'\n", sig_path);
        } else {
            printf("[-] Error guardando firma en archivo.\n");
        }
        OPENSSL_free(signature);
    } else {
        printf("[-] Error: No se pudo generar la firma.\n");
    }
}

/* Procedimiento 3: Verificación interactiva */
static void cli_procedure_verify(void) {
    char pub_path[256] = "public_key.txt";
    char msg_path[256] = "mensaje.txt";
    char sig_path[256] = "firma.txt";
    char line[128];
    int hash_choice = 1;

    printf("\n----------------------------------------------------------------------\n");
    printf("  PROCEDIMIENTO 3: VERIFICACION DE FIRMA DIGITAL RSASSA-PSS\n");
    printf("----------------------------------------------------------------------\n");

    printf("Archivo de clave publica [default: public_key.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(pub_path, line, sizeof(pub_path) - 1);
    }

    printf("Archivo del mensaje/documento original [default: mensaje.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(msg_path, line, sizeof(msg_path) - 1);
    }

    printf("Archivo que contiene la firma digital [default: firma.txt]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > 0) strncpy(sig_path, line, sizeof(sig_path) - 1);
    }

    printf("\nSeleccione funcion Hash con la que fue firmada (SHA2 o SHA3):\n");
    printf("  1. SHA2-256 (Estandar FIPS 186-5)\n");
    printf("  2. SHA2-384\n");
    printf("  3. SHA2-512\n");
    printf("  4. SHA3-256\n");
    printf("  5. SHA3-512\n");
    printf("Seleccion [1-5] [default: 1]: ");
    if (fgets(line, sizeof(line), stdin) && line[0] != '\n') {
        hash_choice = atoi(line);
    }
    const EVP_MD *md = get_hash_algorithm_by_choice(hash_choice);

    printf("\n[*] Verificando firma '%s' para '%s' con clave '%s' [%s]...\n",
           sig_path, msg_path, pub_path, get_hash_name(md));

    bool valid = rsassa_verify_from_files(pub_path, msg_path, sig_path, md);

    printf("\n======================================================================\n");
    printf("   RESULTADO DE LA VERIFICACION (FIPS 186-5): %s\n", valid ? "TRUE (VALIDA)" : "FALSE (INVALIDA)");
    printf("======================================================================\n");
    if (valid) {
        printf("   [OK] La firma digital es AUTENTICA y el mensaje NO ha sido alterado.\n");
    } else {
        printf("   [ALERTA] La firma NO corresponde al mensaje o el archivo fue modificado.\n");
    }
    printf("======================================================================\n");
}

/* Procedimiento 4: Suite de pruebas automatizadas con guardado permanente de archivos */
void run_automated_test_suite(void) {
    printf("\n======================================================================\n");
    printf("   EJECUCION DE SUITE DE PRUEBAS AUTOMATIZADAS (DEMO FIPS 186-5)\n");
    printf("======================================================================\n");

    const char *test_priv = "test_priv.txt";
    const char *test_pub = "test_pub.txt";
    const char *test_msg = "test_msg.txt";
    const char *test_tampered = "test_msg_tampered.txt";
    const char *test_sig = "test_sig.txt";

    /* 1. Crear archivo de mensaje original de prueba */
    FILE *fm = fopen(test_msg, "w");
    if (!fm) {
        printf("[-] Error creando archivo de prueba '%s'.\n", test_msg);
        return;
    }
    fprintf(fm, "Este es un mensaje secreto y crucial para la Practica 5 de Criptografia.\nFIPS 186-5 RSASSA-PSS Validation.\n");
    fclose(fm);
    printf("[1/5] Archivo de mensaje original creado y guardado: '%s'\n", test_msg);

    /* 2. Generar par de llaves en Base64 */
    printf("[2/5] Generando llaves RSA de %d bits en Base64...\n", FIPS_KEY_SIZE);
    if (!rsassa_generate_and_save_keys(FIPS_KEY_SIZE, test_priv, test_pub)) {
        printf("[-] Error generando llaves.\n");
        return;
    }
    printf("      -> Clave privada guardada en: '%s'\n", test_priv);
    printf("      -> Clave publica guardada en: '%s'\n", test_pub);

    /* 3. Firmar mensaje original con SHA-256 */
    printf("[3/5] Firmando '%s' usando rsassa_sign_file con SHA2-256...\n", test_msg);
    size_t sig_len = 0;
    unsigned char *sig = rsassa_sign_file(test_priv, test_msg, &sig_len, EVP_sha256());
    if (!sig) {
        printf("[-] Error firmando mensaje.\n");
        return;
    }
    save_signature_to_file(test_sig, sig, sig_len);
    printf("      -> Firma digital guardada en Base64 en: '%s' (%zu bytes)\n", test_sig, sig_len);

    /* 4. Verificar firma original */
    printf("[4/5] Verificando firma original con rsassa_verify_file...\n");
    bool valid = rsassa_verify_file(test_pub, test_msg, sig, sig_len, EVP_sha256());
    printf("      => Retorno booleano: %s\n", valid ? "TRUE (CORRECTO - FIRMA VALIDA)" : "FALSE (ERROR)");

    /* 5. Prueba de alteración (Tampering): crear archivo alterado sin corromper el original */
    printf("[5/5] Prueba de manipulacion: creando '%s' con 1 byte alterado...\n", test_tampered);
    FILE *fm_alter = fopen(test_tampered, "w");
    if (fm_alter) {
        fprintf(fm_alter, "Este es un mensaje secreto y crucial para la Practica 5 de Criptografia.\nFIPS 186-5 RSASSA-PSS Validation. [MODIFICADO MALICIOSAMENTE]\n");
        fclose(fm_alter);
    }
    bool tampered_valid = rsassa_verify_file(test_pub, test_tampered, sig, sig_len, EVP_sha256());
    printf("      => Retorno con mensaje adulterado: %s\n", tampered_valid ? "TRUE (ERROR)" : "FALSE (CORRECTO - FIRMA RECHAZADA)");

    OPENSSL_free(sig);

    printf("\n======================================================================\n");
    if (valid && !tampered_valid) {
        printf("   TODAS LAS PRUEBAS PASARON EXITOSAMENTE (FIPS 186-5 COMPLIANT)\n");
    } else {
        printf("   FALLO EN AL MENOS UNA PRUEBA\n");
    }
    printf("======================================================================\n");
    printf("[+] Archivos de salida conservados en el directorio actual:\n");
    printf("    1. Clave privada (Base64): '%s'\n", test_priv);
    printf("    2. Clave publica (Base64): '%s'\n", test_pub);
    printf("    3. Mensaje original:       '%s'\n", test_msg);
    printf("    4. Mensaje alterado:       '%s'\n", test_tampered);
    printf("    5. Firma digital (Base64): '%s'\n", test_sig);
    printf("======================================================================\n");
}

/* Loop principal interactivo */
void interactive_cli(void) {
    int opcion = 0;
    char line[64];

    do {
        show_menu();
        if (!fgets(line, sizeof(line), stdin)) break;
        if (sscanf(line, "%d", &opcion) != 1) {
            printf("\n[!] Entrada no valida. Intente de nuevo.\n");
            continue;
        }

        switch (opcion) {
            case 1:
                cli_procedure_keygen();
                break;
            case 2:
                cli_procedure_sign();
                break;
            case 3:
                cli_procedure_verify();
                break;
            case 4:
                run_automated_test_suite();
                break;
            case 5:
                printf("\nSaliendo del programa. Hasta luego!\n");
                break;
            default:
                printf("\n[!] Opcion no valida. Seleccione entre 1 y 5.\n");
                break;
        }
    } while (opcion != 5);
}

/* =========================================================================
 * MAIN: SOPORTA TANTO MODO INTERACTIVO COMO BATCH / CLI ARGUMENTS
 * ========================================================================= */

int main(int argc, char *argv[]) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Si se pasan argumentos por línea de comandos */
    if (argc > 1) {
        if (strcmp(argv[1], "--test") == 0 || strcmp(argv[1], "-t") == 0) {
            run_automated_test_suite();
            return 0;
        }

        if ((strcmp(argv[1], "--keygen") == 0 || strcmp(argv[1], "-k") == 0) && argc >= 4) {
            const char *priv = argv[2];
            const char *pub = argv[3];
            int bits = (argc >= 5) ? atoi(argv[4]) : FIPS_KEY_SIZE;
            printf("[*] Generando llaves RSASSA-PSS (%d bits)...\n", bits);
            if (rsassa_generate_and_save_keys(bits, priv, pub)) {
                printf("[+] Llaves guardadas exitosamente en '%s' y '%s'\n", priv, pub);
                return 0;
            } else {
                fprintf(stderr, "[-] Error generando llaves.\n");
                return 1;
            }
        }

        if ((strcmp(argv[1], "--sign") == 0 || strcmp(argv[1], "-s") == 0) && argc >= 5) {
            const char *priv = argv[2];
            const char *msg = argv[3];
            const char *sig_out = argv[4];
            const EVP_MD *md = EVP_sha256();
            if (argc >= 6) {
                if (strcasecmp(argv[5], "sha384") == 0) md = EVP_sha384();
                else if (strcasecmp(argv[5], "sha512") == 0) md = EVP_sha512();
                else if (strcasecmp(argv[5], "sha3-256") == 0) md = EVP_sha3_256();
                else if (strcasecmp(argv[5], "sha3-512") == 0) md = EVP_sha3_512();
            }

            size_t sig_len = 0;
            unsigned char *sig = rsassa_sign_file(priv, msg, &sig_len, md);
            if (!sig) {
                fprintf(stderr, "[-] Error al generar la firma.\n");
                return 1;
            }
            save_signature_to_file(sig_out, sig, sig_len);
            printf("[+] Firma generada con %s y guardada en '%s'\n", get_hash_name(md), sig_out);
            OPENSSL_free(sig);
            return 0;
        }

        if ((strcmp(argv[1], "--verify") == 0 || strcmp(argv[1], "-v") == 0) && argc >= 5) {
            const char *pub = argv[2];
            const char *msg = argv[3];
            const char *sig_in = argv[4];
            const EVP_MD *md = EVP_sha256();
            if (argc >= 6) {
                if (strcasecmp(argv[5], "sha384") == 0) md = EVP_sha384();
                else if (strcasecmp(argv[5], "sha512") == 0) md = EVP_sha512();
                else if (strcasecmp(argv[5], "sha3-256") == 0) md = EVP_sha3_256();
                else if (strcasecmp(argv[5], "sha3-512") == 0) md = EVP_sha3_512();
            }

            bool ok = rsassa_verify_from_files(pub, msg, sig_in, md);
            printf("Resultado de la verificacion: %s\n", ok ? "true (VALIDA)" : "false (INVALIDA)");
            return ok ? 0 : 2;
        }

        printf("Uso:\n");
        printf("  Modo interactivo (menu CLI): %s\n", argv[0]);
        printf("  Generar llaves:  %s --keygen <priv.txt> <pub.txt> [bits]\n", argv[0]);
        printf("  Firmar archivo:  %s --sign <priv.txt> <mensaje.txt> <firma.txt> [hash]\n", argv[0]);
        printf("  Verificar firma: %s --verify <pub.txt> <mensaje.txt> <firma.txt> [hash]\n", argv[0]);
        printf("  Suite de prueba: %s --test\n", argv[0]);
        return 0;
    }

    /* Modo interactivo por defecto */
    interactive_cli();
    return 0;
}
