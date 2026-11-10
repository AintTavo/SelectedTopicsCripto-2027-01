#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <gmp.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

// -----------------------------------------------------------------------------
// Definición de constantes y códigos de retorno
// -----------------------------------------------------------------------------

#define OK      0
#define ERROR   1

#define MAGIC_RSAC 0x43415352 // "RSAC" para archivos cifrados con RSA escolar
#define MAGIC_AESC 0x43534541 // "AESC" para archivos cifrados con AES-128 (sin CTR)
#define AES_128_KEY_BYTES 16
#define DEFAULT_OAEP_BITS 3072

// -----------------------------------------------------------------------------
// Estructuras de datos para Llaves RSA Escolar con CRT (Sección 1 - GMP)
// -----------------------------------------------------------------------------

/* Estructura para Llave Privada RSA Escolar con soporte para CRT */
typedef struct {
    mpz_t p;    /* Primer factor primo de n */
    mpz_t q;    /* Segundo factor primo de n */
    mpz_t n;    /* Módulo RSA: n = p * q */
    mpz_t d;    /* Exponente privado: d = e^(-1) mod phi(n) */
    mpz_t d_p;  /* Exponente CRT para p: d_p = d mod (p - 1) */
    mpz_t d_q;  /* Exponente CRT para q: d_q = d mod (q - 1) */
} rsa_sc_pri_key_t;

/* Estructura para Llave Pública RSA Escolar */
typedef struct {
    mpz_t e;    /* Exponente público */
    mpz_t n;    /* Módulo RSA: n = p * q */
} rsa_sc_pub_key_t;

/* Estructura que agrupa el par de llaves (Pública y Privada) */
typedef struct {
    rsa_sc_pri_key_t priv;
    rsa_sc_pub_key_t pub;
} rsa_sc_t;

// -----------------------------------------------------------------------------
// Prototipos de funciones - SECCIÓN 1 (Schoolbook RSA con CRT - GMP)
// -----------------------------------------------------------------------------

void rsa_pub_init(rsa_sc_pub_key_t* pub);
void rsa_pub_clear(rsa_sc_pub_key_t* pub);
void rsa_priv_init(rsa_sc_pri_key_t* priv);
void rsa_priv_clear(rsa_sc_pri_key_t* priv);
void rsa_keys_init(rsa_sc_t* keys);
void rsa_keys_clear(rsa_sc_t* keys);

void init_gmp_rand(gmp_randstate_t state);
int gen_key(rsa_sc_t* out_keys, size_t bits);
int exp_bin(mpz_t rop, const mpz_t x, const mpz_t H, const mpz_t n);
int ctr(mpz_t rop, const mpz_t c, const rsa_sc_pri_key_t* priv);
int rsa_encrypt_int(mpz_t c, const rsa_sc_pub_key_t* pub, const mpz_t m);
int rsa_decrypt_int(mpz_t m, const rsa_sc_pri_key_t* priv, const mpz_t c);

int rsa_encrypt(const char* in_filename, const char* out_filename, rsa_sc_pub_key_t pub);
int rsa_decrypt(const char* in_filename, const char* out_filename, rsa_sc_pri_key_t priv);

int rsa_save_pub_key(const char* filepath, const rsa_sc_pub_key_t* pub);
int rsa_load_pub_key(const char* filepath, rsa_sc_pub_key_t* pub);
int rsa_save_priv_key(const char* filepath, const rsa_sc_pri_key_t* priv);
int rsa_load_priv_key(const char* filepath, rsa_sc_pri_key_t* priv);

int run_automated_tests(void);

// -----------------------------------------------------------------------------
// Prototipos de funciones - SECCIÓN 2 (RSA-OAEP con CRT y AES-128 - OpenSSL)
// -----------------------------------------------------------------------------

char* base64_encode(const unsigned char* input, size_t length);
unsigned char* base64_decode(const char* input, size_t* out_len);
int write_text_file(const char* filename, const char* text);
char* read_text_file(const char* filename);

/* 2.1: Generación de par de llaves RSA-OAEP con CRT en archivos Base64 */
int oaep_generate_keypair_files(int bits, const char* pub_file, const char* priv_file);
EVP_PKEY* oaep_load_public_key_b64(const char* pub_file);
EVP_PKEY* oaep_load_private_key_b64(const char* priv_file);
void oaep_inspect_crt_params(EVP_PKEY* pkey);

/* 2.2: Generación de llave aleatoria K de 128 bits y cifrado/descifrado con AES-128 plano (sin CTR) */
int aes128_generate_key(unsigned char key[AES_128_KEY_BYTES], char** out_b64);
int aes128_encrypt_file_ex(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES], bool write_header);
int aes128_encrypt_file(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]);
int aes128_encrypt_file_raw(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]);
int aes128_decrypt_file_ex(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES], bool ignore_header);
int aes128_decrypt_file(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]);
int aes128_decrypt_file_raw(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]);

/* 2.3: Cifrar llave K usando llave pública RSA-OAEP y guardar en Base64 */
int rsa_oaep_encrypt_key_to_file(
    const char* pub_key_file,
    const unsigned char* k_bytes,
    size_t k_len,
    const char* out_enc_key_file
);

/* 2.4: Descifrar llave K cifrada usando llave privada RSA-OAEP con CRT e imprimir en Base64 */
int rsa_oaep_decrypt_key_from_file(
    const char* priv_key_file,
    const char* in_enc_key_file,
    unsigned char** out_k_bytes,
    size_t* out_k_len
);

/* 2.5: Simulación completa del protocolo de transporte de llaves (Alice y Bob) */
int run_alice_bob_oaep_simulation(
    int rsa_bits,
    const char* alice_pub_file,
    const char* alice_priv_file,
    const char* plain_file,
    const char* cipher_file,
    const char* enc_key_file,
    const char* recovered_file
);

void run_interactive_cli(void);

// -----------------------------------------------------------------------------
// MAIN: Soporta tanto modo interactivo (Menú CLI) como banderas por consola
// -----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--test") == 0) {
            return run_automated_tests();
        } else if (strcmp(argv[1], "--test-oaep") == 0) {
            const char* pub_f  = (argc > 2) ? argv[2] : "alice_oaep_pub.b64";
            const char* priv_f = (argc > 3) ? argv[3] : "alice_oaep_priv.b64";
            const char* msg_f  = (argc > 4) ? argv[4] : "mensaje_bob.txt";
            const char* enc_f  = (argc > 5) ? argv[5] : "mensaje_bob.aes.enc";
            const char* key_f  = (argc > 6) ? argv[6] : "llave_k_oaep.b64";
            const char* rec_f  = (argc > 7) ? argv[7] : "mensaje_alice_recuperado.txt";
            return run_alice_bob_oaep_simulation(DEFAULT_OAEP_BITS, pub_f, priv_f, msg_f, enc_f, key_f, rec_f);
        } else if (strcmp(argv[1], "--keygen") == 0 && argc >= 5) {
            size_t bits = (size_t)atoi(argv[2]);
            rsa_sc_t keys;
            rsa_keys_init(&keys);
            if (gen_key(&keys, bits) != OK) {
                rsa_keys_clear(&keys);
                return ERROR;
            }
            rsa_save_pub_key(argv[3], &keys.pub);
            rsa_save_priv_key(argv[4], &keys.priv);
            rsa_keys_clear(&keys);
            return OK;
        } else if (strcmp(argv[1], "--encrypt-file") == 0 && argc >= 5) {
            rsa_sc_pub_key_t pub;
            rsa_pub_init(&pub);
            if (rsa_load_pub_key(argv[2], &pub) != OK) {
                rsa_pub_clear(&pub);
                return ERROR;
            }
            int res = rsa_encrypt(argv[3], argv[4], pub);
            rsa_pub_clear(&pub);
            return res;
        } else if (strcmp(argv[1], "--decrypt-file") == 0 && argc >= 5) {
            rsa_sc_pri_key_t priv;
            rsa_priv_init(&priv);
            if (rsa_load_priv_key(argv[2], &priv) != OK) {
                rsa_priv_clear(&priv);
                return ERROR;
            }
            int res = rsa_decrypt(argv[3], argv[4], priv);
            rsa_priv_clear(&priv);
            return res;
        } else if (strcmp(argv[1], "--oaep-keygen") == 0 && argc >= 5) {
            int bits = atoi(argv[2]);
            return oaep_generate_keypair_files(bits, argv[3], argv[4]);
        } else if ((strcmp(argv[1], "--aes-encrypt") == 0 || strcmp(argv[1], "--aes-encrypt-raw") == 0) && argc >= 5) {
            bool write_hdr = (strcmp(argv[1], "--aes-encrypt-raw") != 0);
            if (argc >= 6 && (strcmp(argv[5], "--no-header") == 0 ||
                              strcmp(argv[5], "--ignore-header") == 0 ||
                              strcmp(argv[5], "--raw") == 0)) {
                write_hdr = false;
            }
            unsigned char k[AES_128_KEY_BYTES];
            char* k_b64 = NULL;
            if (aes128_generate_key(k, &k_b64) != OK) return ERROR;
            write_text_file(argv[4], k_b64);
            printf("[✓] Llave AES-128 (Base64) guardada en '%s'\n", argv[4]);
            free(k_b64);
            return aes128_encrypt_file_ex(argv[2], argv[3], k, write_hdr);
        } else if (strcmp(argv[1], "--oaep-wrap-key") == 0 && argc >= 5) {
            char* k_b64 = read_text_file(argv[3]);
            if (!k_b64) return ERROR;
            size_t k_len = 0;
            unsigned char* k_raw = base64_decode(k_b64, &k_len);
            free(k_b64);
            if (!k_raw) return ERROR;
            int res = rsa_oaep_encrypt_key_to_file(argv[2], k_raw, k_len, argv[4]);
            OPENSSL_cleanse(k_raw, k_len);
            free(k_raw);
            return res;
        } else if (strcmp(argv[1], "--oaep-unwrap-key") == 0 && argc >= 4) {
            unsigned char* k_raw = NULL;
            size_t k_len = 0;
            int res = rsa_oaep_decrypt_key_from_file(argv[2], argv[3], &k_raw, &k_len);
            if (res == OK && argc >= 5 && k_raw) {
                char* k_b64 = base64_encode(k_raw, k_len);
                if (k_b64) {
                    write_text_file(argv[4], k_b64);
                    printf("[✓] Llave K recuperada guardada en '%s'\n", argv[4]);
                    free(k_b64);
                }
            }
            if (k_raw) {
                OPENSSL_cleanse(k_raw, k_len);
                free(k_raw);
            }
            return res;
        } else if ((strcmp(argv[1], "--aes-decrypt") == 0 ||
                    strcmp(argv[1], "--aes-decrypt-raw") == 0 ||
                    strcmp(argv[1], "--aes-decrypt-no-header") == 0) && argc >= 5) {
            bool ign_hdr = (strcmp(argv[1], "--aes-decrypt-raw") == 0 ||
                            strcmp(argv[1], "--aes-decrypt-no-header") == 0);
            if (argc >= 6 && (strcmp(argv[5], "--ignore-header") == 0 ||
                              strcmp(argv[5], "--no-header") == 0 ||
                              strcmp(argv[5], "--raw") == 0)) {
                ign_hdr = true;
            }
            char* k_b64 = read_text_file(argv[4]);
            if (!k_b64) return ERROR;
            size_t k_len = 0;
            unsigned char* k_raw = base64_decode(k_b64, &k_len);
            free(k_b64);
            if (!k_raw || k_len != AES_128_KEY_BYTES) {
                if (k_raw) free(k_raw);
                fprintf(stderr, "[-] Error: La llave AES debe ser de 128 bits (16 bytes).\n");
                return ERROR;
            }
            int res = aes128_decrypt_file_ex(argv[2], argv[3], k_raw, ign_hdr);
            OPENSSL_cleanse(k_raw, k_len);
            free(k_raw);
            return res;
        } else {
            printf("Uso de %s:\n", argv[0]);
            printf("  %s                                                           : Menú interactivo completo\n", argv[0]);
            printf("  --- Sección 1: Schoolbook RSA con CRT (GMP) ---\n");
            printf("  %s --test                                                    : Batería de pruebas Sección 1 (5 llaves, 10 msgs)\n", argv[0]);
            printf("  %s --keygen <bits_primo> <pub_file> <priv_file>              : Generar llaves RSA Escolar\n", argv[0]);
            printf("  %s --encrypt-file <pub_file> <in_file> <out_file>            : Cifrar archivo con RSA Escolar\n", argv[0]);
            printf("  %s --decrypt-file <priv_file> <in_file> <out_file>           : Descifrar archivo con RSA-CRT\n", argv[0]);
            printf("  --- Sección 2: RSA-OAEP con CRT y AES-128 (OpenSSL) ---\n");
            printf("  %s --test-oaep [pub] [priv] [in] [enc] [ekey] [out]          : Simulación completa Alice & Bob\n", argv[0]);
            printf("  %s --oaep-keygen <bits_mod> <pub_b64> <priv_b64>             : Generar llaves RSA-OAEP con CRT en Base64\n", argv[0]);
            printf("  %s --aes-encrypt <in_file> <out_enc> <out_k_b64> [--raw]     : Generar K (128b) y cifrar archivo con AES-128\n", argv[0]);
            printf("  %s --oaep-wrap-key <pub_b64> <in_k_b64> <out_ekey>           : Cifrar K con RSA-OAEP y guardar en Base64\n", argv[0]);
            printf("  %s --oaep-unwrap-key <priv_b64> <in_ekey> [out_k]            : Descifrar K con RSA-OAEP-CRT e imprimir en Base64\n", argv[0]);
            printf("  %s --aes-decrypt <in_enc> <out_file> <in_k_b64> [--raw]     : Descifrar archivo con K y AES-128 (soporta --raw o auto-detección)\n", argv[0]);
            printf("  %s --aes-decrypt-raw <in_enc> <out_file> <in_k_b64>         : Descifrar ciphertext AES crudo ignorando cabecera AESC\n", argv[0]);
            return ERROR;
        }
    }

    run_interactive_cli();
    return OK;
}

// =============================================================================
// SECCIÓN 1: SCHOOLBOOK RSA CON TEOREMA CHINO DEL RESIDUO (GMP)
// =============================================================================

void rsa_pub_init(rsa_sc_pub_key_t* pub) {
    mpz_inits(pub->e, pub->n, NULL);
}

void rsa_pub_clear(rsa_sc_pub_key_t* pub) {
    mpz_clears(pub->e, pub->n, NULL);
}

void rsa_priv_init(rsa_sc_pri_key_t* priv) {
    mpz_inits(priv->p, priv->q, priv->n, priv->d, priv->d_p, priv->d_q, NULL);
}

void rsa_priv_clear(rsa_sc_pri_key_t* priv) {
    mpz_clears(priv->p, priv->q, priv->n, priv->d, priv->d_p, priv->d_q, NULL);
}

void rsa_keys_init(rsa_sc_t* keys) {
    rsa_priv_init(&keys->priv);
    rsa_pub_init(&keys->pub);
}

void rsa_keys_clear(rsa_sc_t* keys) {
    rsa_priv_clear(&keys->priv);
    rsa_pub_clear(&keys->pub);
}

void init_gmp_rand(gmp_randstate_t state) {
    gmp_randinit_default(state);
    unsigned long seed = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) != (ssize_t)sizeof(seed)) {
            seed = (unsigned long)time(NULL) ^ (unsigned long)getpid();
        }
        close(fd);
    } else {
        seed = (unsigned long)time(NULL) ^ (unsigned long)getpid();
    }
    gmp_randseed_ui(state, seed);
}

// -----------------------------------------------------------------------------
// Ejercicio 1.1: Generador de Llaves RSA Escolar con CRT
// -----------------------------------------------------------------------------

int gen_key(rsa_sc_t* out_keys, size_t bits) {
    if (bits < 4) {
        fprintf(stderr, "[-] Error: el tamaño en bits debe ser mayor o igual a 4 bits.\n");
        return ERROR;
    }

    gmp_randstate_t state;
    init_gmp_rand(state);

    mpz_t tmp_p1, tmp_q1, phi, tmp_gcd;
    mpz_inits(tmp_p1, tmp_q1, phi, tmp_gcd, NULL);

    // 1. Generación del primo p (|p| = bits) usando mpz_nextprime de GMP
    do {
        mpz_urandomb(out_keys->priv.p, state, bits);
        mpz_setbit(out_keys->priv.p, bits - 1);
        mpz_setbit(out_keys->priv.p, 0);
        mpz_nextprime(out_keys->priv.p, out_keys->priv.p);
    } while (mpz_sizeinbase(out_keys->priv.p, 2) < bits);

    // 2. Generación del primo q (|q| = bits, q != p)
    do {
        mpz_urandomb(out_keys->priv.q, state, bits);
        mpz_setbit(out_keys->priv.q, bits - 1);
        mpz_setbit(out_keys->priv.q, 0);
        mpz_nextprime(out_keys->priv.q, out_keys->priv.q);
    } while (mpz_cmp(out_keys->priv.p, out_keys->priv.q) == 0 ||
             mpz_sizeinbase(out_keys->priv.q, 2) < bits);

    if (mpz_cmp(out_keys->priv.p, out_keys->priv.q) < 0) {
        mpz_swap(out_keys->priv.p, out_keys->priv.q);
    }

    // 3. Módulo n = p * q
    mpz_mul(out_keys->priv.n, out_keys->priv.p, out_keys->priv.q);
    mpz_set(out_keys->pub.n, out_keys->priv.n);

    // 4. phi(n) = (p - 1) * (q - 1)
    mpz_sub_ui(tmp_p1, out_keys->priv.p, 1);
    mpz_sub_ui(tmp_q1, out_keys->priv.q, 1);
    mpz_mul(phi, tmp_p1, tmp_q1);

    // 5. Exponente público e aleatorio: gcd(e, phi) == 1, e != 3, e != 65537
    size_t phi_bits = mpz_sizeinbase(phi, 2);
    size_t e_bits = (phi_bits > 16) ? (phi_bits / 2 + 1) : (phi_bits - 1);
    if (e_bits < 4) e_bits = phi_bits - 1;
    if (e_bits < 3) e_bits = 3;

    int attempts = 0;
    while (1) {
        attempts++;
        if (phi_bits > 4) {
            mpz_urandomb(out_keys->pub.e, state, e_bits);
            mpz_setbit(out_keys->pub.e, 0);
            if (mpz_cmp_ui(out_keys->pub.e, 3) <= 0) {
                mpz_add_ui(out_keys->pub.e, out_keys->pub.e, 4);
            }
        } else {
            mpz_set_ui(out_keys->pub.e, 5);
        }

        if (mpz_cmp_ui(out_keys->pub.e, 3) == 0) continue;
        if (mpz_cmp_ui(out_keys->pub.e, 65537) == 0) continue;

        if (mpz_cmp_ui(out_keys->pub.e, 1) > 0 && mpz_cmp(out_keys->pub.e, phi) < 0) {
            mpz_gcd(tmp_gcd, out_keys->pub.e, phi);
            if (mpz_cmp_ui(tmp_gcd, 1) == 0) {
                break;
            }
        }

        if (attempts > 50000) {
            mpz_add_ui(out_keys->pub.e, out_keys->pub.e, 2);
            if (mpz_cmp(out_keys->pub.e, phi) >= 0) {
                mpz_set_ui(out_keys->pub.e, 5);
            }
            if (mpz_cmp_ui(out_keys->pub.e, 3) == 0 || mpz_cmp_ui(out_keys->pub.e, 65537) == 0) {
                continue;
            }
            mpz_gcd(tmp_gcd, out_keys->pub.e, phi);
            if (mpz_cmp_ui(tmp_gcd, 1) == 0) {
                break;
            }
        }
    }

    // 6. Exponente privado d = e^(-1) mod phi(n)
    if (mpz_invert(out_keys->priv.d, out_keys->pub.e, phi) == 0) {
        mpz_clears(tmp_p1, tmp_q1, phi, tmp_gcd, NULL);
        gmp_randclear(state);
        return ERROR;
    }

    // 7. Componentes CRT: dp = d mod (p - 1), dq = d mod (q - 1)
    mpz_mod(out_keys->priv.d_p, out_keys->priv.d, tmp_p1);
    mpz_mod(out_keys->priv.d_q, out_keys->priv.d, tmp_q1);

    printf("\n======================================================================\n");
    printf("                PAR DE LLAVES GENERADO (RSA - CRT)                    \n");
    printf("======================================================================\n");
    printf(" [LLAVE PÚBLICA] (e, n):\n");
    gmp_printf("   e  = %Zd\n", out_keys->pub.e);
    gmp_printf("   n  = %Zd  (%zu bits)\n", out_keys->pub.n, mpz_sizeinbase(out_keys->pub.n, 2));
    printf(" ----------------------------------------------------------------------\n");
    printf(" [LLAVE PRIVADA] Tupla (p, q, n, d, dp, dq):\n");
    gmp_printf("   p  = %Zd  (%zu bits)\n", out_keys->priv.p, mpz_sizeinbase(out_keys->priv.p, 2));
    gmp_printf("   q  = %Zd  (%zu bits)\n", out_keys->priv.q, mpz_sizeinbase(out_keys->priv.q, 2));
    gmp_printf("   n  = %Zd\n", out_keys->priv.n);
    gmp_printf("   d  = %Zd\n", out_keys->priv.d);
    gmp_printf("   dp = %Zd\n", out_keys->priv.d_p);
    gmp_printf("   dq = %Zd\n", out_keys->priv.d_q);
    printf("======================================================================\n\n");

    mpz_clears(tmp_p1, tmp_q1, phi, tmp_gcd, NULL);
    gmp_randclear(state);
    return OK;
}

// -----------------------------------------------------------------------------
// Ejercicio 1.2: Algoritmo 1: Square and Multiply(x, H, n)
// -----------------------------------------------------------------------------

int exp_bin(mpz_t rop, const mpz_t x, const mpz_t H, const mpz_t n) {
    if (mpz_cmp_ui(n, 0) <= 0) {
        return ERROR;
    }

    if (mpz_cmp_ui(H, 0) == 0) {
        mpz_set_ui(rop, 1);
        mpz_mod(rop, rop, n);
        return OK;
    }

    size_t t = mpz_sizeinbase(H, 2);
    mpz_t r, x_red;
    mpz_inits(r, x_red, NULL);

    mpz_mod(x_red, x, n);

    // Paso 1: r <- x mod n (bit más significativo b_{t-1} = 1)
    mpz_set(r, x_red);

    // Pasos 2 a 7: Ciclo para i <- t - 2 descendiendo hasta 0
    if (t > 1) {
        for (ssize_t i = (ssize_t)t - 2; i >= 0; i--) {
            // Paso 3: r <- r^2 mod n
            mpz_mul(r, r, r);
            mpz_mod(r, r, n);

            // Paso 4: if b_i == 1 then
            if (mpz_tstbit(H, (mp_bitcnt_t)i) == 1) {
                // Paso 5: r <- r * x mod n
                mpz_mul(r, r, x_red);
                mpz_mod(r, r, n);
            }
        }
    }

    mpz_set(rop, r);
    mpz_clears(r, x_red, NULL);
    return OK;
}

// -----------------------------------------------------------------------------
// Ejercicio 1.4: Teorema Chino del Residuo (CRT)
// -----------------------------------------------------------------------------

int ctr(mpz_t rop, const mpz_t c, const rsa_sc_pri_key_t* priv) {
    if (mpz_cmp_ui(priv->p, 0) <= 0 || mpz_cmp_ui(priv->q, 0) <= 0 || mpz_cmp_ui(priv->n, 0) <= 0) {
        return ERROR;
    }

    mpz_t mp, mq, qInv, pInv, h, m_garner, m_gauss, tmp;
    mpz_inits(mp, mq, qInv, pInv, h, m_garner, m_gauss, tmp, NULL);

    mpz_t c_p, c_q;
    mpz_inits(c_p, c_q, NULL);
    mpz_mod(c_p, c, priv->p);
    mpz_mod(c_q, c, priv->q);

    printf("\n----------------------------------------------------------------------\n");
    printf("          DESGLOSE PASO A PASO: TEOREMA CHINO DEL RESIDUO (CRT)        \n");
    printf("----------------------------------------------------------------------\n");
    gmp_printf(" Ciphertext de entrada c = %Zd\n\n", c);

    // 1. mp = c^dp mod p
    exp_bin(mp, c_p, priv->d_p, priv->p);
    gmp_printf(" [Paso 1] m_p = (c mod p)^dp mod p\n");
    gmp_printf("          m_p = %Zd\n\n", mp);

    // 2. mq = c^dq mod q
    exp_bin(mq, c_q, priv->d_q, priv->q);
    gmp_printf(" [Paso 2] m_q = (c mod q)^dq mod q\n");
    gmp_printf("          m_q = %Zd\n\n", mq);

    // 3. Inversos modulares
    if (mpz_invert(qInv, priv->q, priv->p) == 0) {
        fprintf(stderr, "[-] Error: q no es invertible modulo p.\n");
        mpz_clears(mp, mq, qInv, pInv, h, m_garner, m_gauss, tmp, c_p, c_q, NULL);
        return ERROR;
    }
    gmp_printf(" [Paso 3] Inverso qInv = q^(-1) mod p (NIST SP 800-56B)\n");
    gmp_printf("          qInv = %Zd\n", qInv);

    if (mpz_invert(pInv, priv->p, priv->q) != 0) {
        gmp_printf("          pInv = p^(-1) mod q = %Zd (Gauss)\n\n", pInv);
    }

    // 4. Coeficiente h de Garner: h = ((m_p - m_q) * qInv) mod p
    mpz_sub(tmp, mp, mq);
    mpz_mod(tmp, tmp, priv->p);
    if (mpz_sgn(tmp) < 0) {
        mpz_add(tmp, tmp, priv->p);
    }
    mpz_mul(h, tmp, qInv);
    mpz_mod(h, h, priv->p);
    gmp_printf(" [Paso 4] Coeficiente h (Garner) = ((m_p - m_q) * qInv) mod p\n");
    gmp_printf("          h = %Zd\n\n", h);

    // 5. Reconstrucción: m = m_q + (h * q) mod n
    mpz_mul(tmp, h, priv->q);
    mpz_add(m_garner, mq, tmp);
    mpz_mod(m_garner, m_garner, priv->n);
    gmp_printf(" [Paso 5] Mensaje recuperado m (Algoritmo de Garner):\n");
    gmp_printf("          m = m_q + (h * q) = %Zd\n\n", m_garner);

    // Verificación con la formulación de Gauss
    mpz_t g1, g2;
    mpz_inits(g1, g2, NULL);
    mpz_mul(g1, mp, priv->q);
    mpz_mul(g1, g1, qInv);
    mpz_mul(g2, mq, priv->p);
    mpz_mul(g2, g2, pInv);
    mpz_add(m_gauss, g1, g2);
    mpz_mod(m_gauss, m_gauss, priv->n);
    gmp_printf(" [Verif.] Mensaje recuperado m (Formulación de Gauss):\n");
    gmp_printf("          m = (m_p*q*qInv + m_q*p*pInv) mod n = %Zd\n", m_gauss);
    printf("----------------------------------------------------------------------\n\n");

    mpz_set(rop, m_garner);

    mpz_clears(mp, mq, qInv, pInv, h, m_garner, m_gauss, tmp, c_p, c_q, g1, g2, NULL);
    return OK;
}

static int ctr_silent(mpz_t rop, const mpz_t c, const rsa_sc_pri_key_t* priv) {
    if (mpz_cmp_ui(priv->p, 0) <= 0 || mpz_cmp_ui(priv->q, 0) <= 0) return ERROR;

    mpz_t mp, mq, qInv, h, tmp, c_p, c_q;
    mpz_inits(mp, mq, qInv, h, tmp, c_p, c_q, NULL);

    mpz_mod(c_p, c, priv->p);
    mpz_mod(c_q, c, priv->q);

    exp_bin(mp, c_p, priv->d_p, priv->p);
    exp_bin(mq, c_q, priv->d_q, priv->q);

    if (mpz_invert(qInv, priv->q, priv->p) == 0) {
        mpz_clears(mp, mq, qInv, h, tmp, c_p, c_q, NULL);
        return ERROR;
    }

    mpz_sub(tmp, mp, mq);
    mpz_mod(tmp, tmp, priv->p);
    if (mpz_sgn(tmp) < 0) mpz_add(tmp, tmp, priv->p);

    mpz_mul(h, tmp, qInv);
    mpz_mod(h, h, priv->p);

    mpz_mul(tmp, h, priv->q);
    mpz_add(rop, mq, tmp);
    mpz_mod(rop, rop, priv->n);

    mpz_clears(mp, mq, qInv, h, tmp, c_p, c_q, NULL);
    return OK;
}

// -----------------------------------------------------------------------------
// Ejercicio 1.3 y 1.4: Cifrado y Descifrado RSA Escolar de un Entero
// -----------------------------------------------------------------------------

int rsa_encrypt_int(mpz_t c, const rsa_sc_pub_key_t* pub, const mpz_t m) {
    if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, pub->n) >= 0) {
        fprintf(stderr, "[-] Error: El mensaje debe cumplir la condición 0 < m < n.\n");
        return ERROR;
    }

    int res = exp_bin(c, m, pub->e, pub->n);
    if (res == OK) {
        printf("\n======================================================\n");
        printf("           CIFRADO RSA ESCOLAR DE ENTERO              \n");
        printf("======================================================\n");
        gmp_printf(" Mensaje en claro m = %Zd\n", m);
        gmp_printf(" Ciphertext c       = %Zd\n", c);
        printf("======================================================\n\n");
    }
    return res;
}

int rsa_decrypt_int(mpz_t m, const rsa_sc_pri_key_t* priv, const mpz_t c) {
    if (mpz_cmp_ui(c, 0) <= 0 || mpz_cmp(c, priv->n) >= 0) {
        fprintf(stderr, "[-] Error: El ciphertext debe cumplir la condición 0 < c < n.\n");
        return ERROR;
    }

    int res = ctr(m, c, priv);
    if (res == OK) {
        printf("\n======================================================\n");
        printf("          RESULTADO DEL DESCIFRADO RSA-CRT            \n");
        printf("======================================================\n");
        gmp_printf(" Ciphertext c       = %Zd\n", c);
        gmp_printf(" Mensaje descifrado = %Zd\n", m);
        printf("======================================================\n\n");
    }
    return res;
}

// -----------------------------------------------------------------------------
// Cifrado y Descifrado de Archivos por Bloques (RSA Escolar)
// -----------------------------------------------------------------------------

int rsa_encrypt(const char* in_filename, const char* out_filename, rsa_sc_pub_key_t pub) {
    FILE* fin = fopen(in_filename, "rb");
    if (!fin) {
        fprintf(stderr, "[-] Error al abrir archivo de entrada: %s\n", in_filename);
        return ERROR;
    }

    FILE* fout = fopen(out_filename, "wb");
    if (!fout) {
        fprintf(stderr, "[-] Error al crear archivo de salida: %s\n", out_filename);
        fclose(fin);
        return ERROR;
    }

    size_t n_bits = mpz_sizeinbase(pub.n, 2);
    size_t n_len = (n_bits + 7) / 8;
    if (n_len < 2) {
        fprintf(stderr, "[-] Error: Llave demasiado corta para cifrado de archivos (se requiere n >= 16 bits).\n");
        fclose(fin);
        fclose(fout);
        return ERROR;
    }

    size_t chunk_len = n_len - 1;

    fseek(fin, 0, SEEK_END);
    uint64_t file_size = (uint64_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);

    uint32_t magic = MAGIC_RSAC;
    uint32_t n_len_u32 = (uint32_t)n_len;
    uint32_t chunk_len_u32 = (uint32_t)chunk_len;

    fwrite(&magic, sizeof(uint32_t), 1, fout);
    fwrite(&n_len_u32, sizeof(uint32_t), 1, fout);
    fwrite(&chunk_len_u32, sizeof(uint32_t), 1, fout);
    fwrite(&file_size, sizeof(uint64_t), 1, fout);

    uint8_t* in_buf = (uint8_t*)malloc(chunk_len);
    uint8_t* out_buf = (uint8_t*)malloc(n_len);
    if (!in_buf || !out_buf) {
        fclose(fin); fclose(fout);
        free(in_buf); free(out_buf);
        return ERROR;
    }

    mpz_t m, c;
    mpz_inits(m, c, NULL);

    size_t bytes_read = 0;
    size_t blocks_count = 0;

    printf("[+] Cifrando archivo: %s -> %s\n", in_filename, out_filename);
    printf("    Tamano original: %llu bytes | Bloque de texto claro: %zu bytes | Bloque cifrado: %zu bytes\n",
           (unsigned long long)file_size, chunk_len, n_len);

    while ((bytes_read = fread(in_buf, 1, chunk_len, fin)) > 0) {
        mpz_import(m, bytes_read, 1, 1, 1, 0, in_buf);
        exp_bin(c, m, pub.e, pub.n);

        memset(out_buf, 0, n_len);
        size_t exported_count = 0;
        uint8_t* tmp_exp = (uint8_t*)mpz_export(NULL, &exported_count, 1, 1, 1, 0, c);
        if (tmp_exp) {
            if (exported_count <= n_len) {
                memcpy(out_buf + (n_len - exported_count), tmp_exp, exported_count);
            }
            free(tmp_exp);
        }

        fwrite(out_buf, 1, n_len, fout);
        blocks_count++;
    }

    printf("[✓] Cifrado exitoso: %zu bloques procesados.\n", blocks_count);

    mpz_clears(m, c, NULL);
    free(in_buf);
    free(out_buf);
    fclose(fin);
    fclose(fout);
    return OK;
}

int rsa_decrypt(const char* in_filename, const char* out_filename, rsa_sc_pri_key_t priv) {
    FILE* fin = fopen(in_filename, "rb");
    if (!fin) {
        fprintf(stderr, "[-] Error al abrir archivo cifrado: %s\n", in_filename);
        return ERROR;
    }

    uint32_t magic = 0;
    uint32_t n_len_u32 = 0;
    uint32_t chunk_len_u32 = 0;
    uint64_t file_size = 0;

    if (fread(&magic, sizeof(uint32_t), 1, fin) != 1 ||
        fread(&n_len_u32, sizeof(uint32_t), 1, fin) != 1 ||
        fread(&chunk_len_u32, sizeof(uint32_t), 1, fin) != 1 ||
        fread(&file_size, sizeof(uint64_t), 1, fin) != 1) {
        fprintf(stderr, "[-] Error: Archivo danado o formato invalido.\n");
        fclose(fin);
        return ERROR;
    }

    if (magic != MAGIC_RSAC) {
        fprintf(stderr, "[-] Error: Cabecera no valida (no es un archivo cifrado con RSAC).\n");
        fclose(fin);
        return ERROR;
    }

    size_t n_len = (size_t)n_len_u32;
    size_t chunk_len = (size_t)chunk_len_u32;

    FILE* fout = fopen(out_filename, "wb");
    if (!fout) {
        fprintf(stderr, "[-] Error al crear archivo descifrado: %s\n", out_filename);
        fclose(fin);
        return ERROR;
    }

    uint8_t* in_buf = (uint8_t*)malloc(n_len);
    uint8_t* out_buf = (uint8_t*)malloc(chunk_len);
    if (!in_buf || !out_buf) {
        fclose(fin); fclose(fout);
        free(in_buf); free(out_buf);
        return ERROR;
    }

    mpz_t c, m;
    mpz_inits(c, m, NULL);

    uint64_t remaining_bytes = file_size;
    size_t blocks_count = 0;

    printf("[+] Descifrando archivo con CRT: %s -> %s\n", in_filename, out_filename);
    printf("    Tamano a recuperar: %llu bytes | Bloque cifrado: %zu bytes\n",
           (unsigned long long)file_size, n_len);

    while (remaining_bytes > 0 && fread(in_buf, 1, n_len, fin) == n_len) {
        size_t cur_chunk = (remaining_bytes < (uint64_t)chunk_len) ? (size_t)remaining_bytes : chunk_len;

        mpz_import(c, n_len, 1, 1, 1, 0, in_buf);
        ctr_silent(m, c, &priv);

        memset(out_buf, 0, cur_chunk);
        size_t exported_count = 0;
        uint8_t* tmp_exp = (uint8_t*)mpz_export(NULL, &exported_count, 1, 1, 1, 0, m);
        if (tmp_exp) {
            if (exported_count <= cur_chunk) {
                memcpy(out_buf + (cur_chunk - exported_count), tmp_exp, exported_count);
            }
            free(tmp_exp);
        }

        fwrite(out_buf, 1, cur_chunk, fout);
        remaining_bytes -= cur_chunk;
        blocks_count++;
    }

    printf("[✓] Descifrado exitoso: %zu bloques procesados, %llu bytes recuperados.\n",
           blocks_count, (unsigned long long)file_size);

    mpz_clears(c, m, NULL);
    free(in_buf);
    free(out_buf);
    fclose(fin);
    fclose(fout);
    return OK;
}

// -----------------------------------------------------------------------------
// Persistencia de Llaves Escolares en Disco
// -----------------------------------------------------------------------------

int rsa_save_pub_key(const char* filepath, const rsa_sc_pub_key_t* pub) {
    FILE* f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "[-] No se pudo abrir %s para escritura.\n", filepath);
        return ERROR;
    }
    fprintf(f, "# --- INICIO LLAVE PUBLICA RSA ---\n");
    gmp_fprintf(f, "n=%Zd\n", pub->n);
    gmp_fprintf(f, "e=%Zd\n", pub->e);
    fprintf(f, "# --- FIN LLAVE PUBLICA RSA ---\n");
    fclose(f);
    printf("[✓] Llave pública guardada correctamente en '%s'\n", filepath);
    return OK;
}

int rsa_load_pub_key(const char* filepath, rsa_sc_pub_key_t* pub) {
    FILE* f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "[-] No se pudo abrir %s para lectura.\n", filepath);
        return ERROR;
    }
    char line[4096];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (strncmp(line, "n=", 2) == 0) {
            char* val = line + 2;
            val[strcspn(val, "\r\n")] = 0;
            mpz_set_str(pub->n, val, 10);
            loaded++;
        } else if (strncmp(line, "e=", 2) == 0) {
            char* val = line + 2;
            val[strcspn(val, "\r\n")] = 0;
            mpz_set_str(pub->e, val, 10);
            loaded++;
        }
    }
    fclose(f);
    if (loaded == 2) {
        printf("[✓] Llave pública cargada correctamente desde '%s'\n", filepath);
        return OK;
    }
    fprintf(stderr, "[-] Error de formato en archivo de llave pública: %s\n", filepath);
    return ERROR;
}

int rsa_save_priv_key(const char* filepath, const rsa_sc_pri_key_t* priv) {
    FILE* f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "[-] No se pudo abrir %s para escritura.\n", filepath);
        return ERROR;
    }
    fprintf(f, "# --- INICIO LLAVE PRIVADA RSA (CRT) ---\n");
    gmp_fprintf(f, "p=%Zd\n", priv->p);
    gmp_fprintf(f, "q=%Zd\n", priv->q);
    gmp_fprintf(f, "n=%Zd\n", priv->n);
    gmp_fprintf(f, "d=%Zd\n", priv->d);
    gmp_fprintf(f, "dp=%Zd\n", priv->d_p);
    gmp_fprintf(f, "dq=%Zd\n", priv->d_q);
    fprintf(f, "# --- FIN LLAVE PRIVADA RSA (CRT) ---\n");
    fclose(f);
    printf("[✓] Llave privada guardada correctamente en '%s'\n", filepath);
    return OK;
}

int rsa_load_priv_key(const char* filepath, rsa_sc_pri_key_t* priv) {
    FILE* f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "[-] No se pudo abrir %s para lectura.\n", filepath);
        return ERROR;
    }
    char line[4096];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = line;
        char* val = eq + 1;
        val[strcspn(val, "\r\n")] = 0;

        if (strcmp(key, "p") == 0) { mpz_set_str(priv->p, val, 10); loaded++; }
        else if (strcmp(key, "q") == 0) { mpz_set_str(priv->q, val, 10); loaded++; }
        else if (strcmp(key, "n") == 0) { mpz_set_str(priv->n, val, 10); loaded++; }
        else if (strcmp(key, "d") == 0) { mpz_set_str(priv->d, val, 10); loaded++; }
        else if (strcmp(key, "dp") == 0) { mpz_set_str(priv->d_p, val, 10); loaded++; }
        else if (strcmp(key, "dq") == 0) { mpz_set_str(priv->d_q, val, 10); loaded++; }
    }
    fclose(f);
    if (loaded == 6) {
        printf("[✓] Llave privada CRT cargada correctamente desde '%s'\n", filepath);
        return OK;
    }
    fprintf(stderr, "[-] Error de formato en archivo de llave privada: %s\n", filepath);
    return ERROR;
}

// -----------------------------------------------------------------------------
// Ejercicio 1.6: Batería de Pruebas Automáticas (5 llaves, 10 mensajes)
// -----------------------------------------------------------------------------

int run_automated_tests(void) {
    printf("\n======================================================================\n");
    printf("        EJERCICIO 6: BATERÍA DE PRUEBAS AUTOMÁTICAS (5 LLAVES, 10 MSGS)  \n");
    printf("======================================================================\n\n");

    size_t test_bits[5] = {16, 32, 64, 128, 256};
    rsa_sc_t keys[5];
    for (int i = 0; i < 5; i++) {
        rsa_keys_init(&keys[i]);
    }

    printf(">>> FASE 1: GENERANDO 5 PARES DE LLAVES DISTINTOS (RSA-CRT)...\n");
    for (int i = 0; i < 5; i++) {
        printf("\n--- Generando Par de Llaves #%d (|p|=|q| = %zu bits) ---\n", i + 1, test_bits[i]);
        if (gen_key(&keys[i], test_bits[i]) != OK) {
            fprintf(stderr, "[-] Fallo en generacion de llave %d\n", i + 1);
            return ERROR;
        }
    }

    printf("\n>>> FASE 2: CIFRANDO Y DESCIFRANDO 10 MENSAJES DISTINTOS CON CRT...\n");
    const char* sample_messages[10] = {
        "42",
        "1337",
        "65535",
        "1000003",
        "987654321",
        "123456789012345",
        "314159265358979323",
        "27182818284590452353",
        "8675309999999999999999",
        "11223344556677889900112233"
    };

    int tests_passed = 0;

    for (int m_idx = 0; m_idx < 10; m_idx++) {
        int k_idx = m_idx % 5;
        mpz_t m, c, m_rec;
        mpz_inits(m, c, m_rec, NULL);

        mpz_set_str(m, sample_messages[m_idx], 10);
        mpz_mod(m, m, keys[k_idx].pub.n);
        if (mpz_cmp_ui(m, 0) == 0) mpz_set_ui(m, 2);

        printf("\n[Test %02d/10] Probando con Llave #%d (%zu bits n):\n",
               m_idx + 1, k_idx + 1, mpz_sizeinbase(keys[k_idx].pub.n, 2));
        gmp_printf("  - Mensaje claro m: %Zd\n", m);

        exp_bin(c, m, keys[k_idx].pub.e, keys[k_idx].pub.n);
        gmp_printf("  - Ciphertext c   : %Zd\n", c);

        if (m_idx == 0 || m_idx == 4) {
            ctr(m_rec, c, &keys[k_idx].priv);
        } else {
            ctr_silent(m_rec, c, &keys[k_idx].priv);
        }
        gmp_printf("  - Recuperado     : %Zd\n", m_rec);

        if (mpz_cmp(m, m_rec) == 0) {
            printf("  -> [✓] CORRECTO: m == m_rec\n");
            tests_passed++;
        } else {
            printf("  -> [✗] ERROR: Los mensajes no coinciden!\n");
        }

        mpz_clears(m, c, m_rec, NULL);
    }

    printf("\n======================================================================\n");
    printf(" RESULTADO DE LA BATERÍA DE PRUEBAS: %d/10 PRUEBAS EXITOSAS\n", tests_passed);
    printf("======================================================================\n\n");

    for (int i = 0; i < 5; i++) {
        rsa_keys_clear(&keys[i]);
    }
    return (tests_passed == 10) ? OK : ERROR;
}

// =============================================================================
// SECCIÓN 2: RSA-OAEP CON CRT Y AES-128 (OPENSSL 3.5+ EVP API)
// =============================================================================

char* base64_encode(const unsigned char* input, size_t length) {
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

    char* buff = (char*)malloc(bptr->length + 1);
    if (buff) {
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = '\0';
    }
    BIO_free_all(b64);
    return buff;
}

unsigned char* base64_decode(const char* input, size_t* out_len) {
    if (!input || !out_len) return NULL;
    *out_len = 0;

    size_t in_len = strlen(input);
    if (in_len == 0) return NULL;

    char* clean = (char*)malloc(in_len + 1);
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

    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        free(clean);
        return NULL;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bmem = BIO_new_mem_buf(clean, (int)clean_len);
    if (!bmem) {
        BIO_free(b64);
        free(clean);
        return NULL;
    }
    bmem = BIO_push(b64, bmem);

    unsigned char* buffer = (unsigned char*)malloc(clean_len);
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

int write_text_file(const char* filename, const char* text) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "[-] Error al abrir '%s' para escritura.\n", filename);
        return ERROR;
    }
    fprintf(f, "%s\n", text);
    fclose(f);
    return OK;
}

char* read_text_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[-] Error al abrir '%s' para lectura.\n", filename);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    while (rd > 0 && (buf[rd - 1] == '\n' || buf[rd - 1] == '\r' || buf[rd - 1] == ' ')) {
        buf[--rd] = '\0';
    }
    return buf;
}

// -----------------------------------------------------------------------------
// Inspección de los 8 parámetros del formato CRT de NIST SP 800-56B Rev. 2
// (n, e, d, p, q, dP, dQ, qInv) dentro de EVP_PKEY de OpenSSL
// -----------------------------------------------------------------------------

void oaep_inspect_crt_params(EVP_PKEY* pkey) {
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

    if (n && e && d && p && q && dmp1 && dmq1 && iqmp) {
        printf(" [Verificación NIST SP 800-56B Sec. 6.2.2 - Formato CRT de 8 Valores]:\n");
        printf("   1. n    (Módulo RSA)             : %d bits\n", BN_num_bits(n));
        char* e_dec = BN_bn2dec(e);
        printf("   2. e    (Exponente público)      : %s\n", e_dec ? e_dec : "65537");
        OPENSSL_free(e_dec);
        printf("   3. d    (Exponente privado)      : %d bits\n", BN_num_bits(d));
        printf("   4. p    (Primer factor primo)    : %d bits\n", BN_num_bits(p));
        printf("   5. q    (Segundo factor primo)   : %d bits\n", BN_num_bits(q));
        printf("   6. dP   (d mod (p-1))            : %d bits\n", BN_num_bits(dmp1));
        printf("   7. dQ   (d mod (q-1))            : %d bits\n", BN_num_bits(dmq1));
        printf("   8. qInv (q^(-1) mod p)           : %d bits\n", BN_num_bits(iqmp));
    }

    BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
    BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
}

// -----------------------------------------------------------------------------
// Ejercicio 2.1: Generar par de llaves para RSA-OAEP con CRT y guardar en Base64
// -----------------------------------------------------------------------------

int oaep_generate_keypair_files(int bits, const char* pub_file, const char* priv_file) {
    if (bits < 2048) {
        fprintf(stderr, "[!] Advertencia: NIST SP 800-56B Rev. 2 recomienda nBits >= 2048 (usando %d bits).\n", bits);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) return ERROR;

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        fprintf(stderr, "[-] Error al generar el par de llaves RSA-OAEP con CRT en OpenSSL.\n");
        return ERROR;
    }
    EVP_PKEY_CTX_free(ctx);

    printf("\n======================================================================\n");
    printf("       EJERCICIO 2.1: GENERACIÓN DE LLAVES RSA-OAEP CON CRT           \n");
    printf("======================================================================\n");
    oaep_inspect_crt_params(pkey);

    // Serializar llave pública (SubjectPublicKeyInfo DER -> Base64)
    unsigned char* pub_der = NULL;
    int pub_der_len = i2d_PUBKEY(pkey, &pub_der);
    if (pub_der_len <= 0 || !pub_der) {
        EVP_PKEY_free(pkey);
        return ERROR;
    }
    char* pub_b64 = base64_encode(pub_der, (size_t)pub_der_len);
    OPENSSL_free(pub_der);

    // Serializar llave privada con parámetros CRT (PKCS#8 PrivateKeyInfo DER -> Base64)
    unsigned char* priv_der = NULL;
    int priv_der_len = i2d_PrivateKey(pkey, &priv_der);
    if (priv_der_len <= 0 || !priv_der) {
        free(pub_b64);
        EVP_PKEY_free(pkey);
        return ERROR;
    }
    char* priv_b64 = base64_encode(priv_der, (size_t)priv_der_len);
    OPENSSL_clear_free(priv_der, (size_t)priv_der_len);
    EVP_PKEY_free(pkey);

    if (!pub_b64 || !priv_b64) {
        free(pub_b64);
        free(priv_b64);
        return ERROR;
    }

    if (write_text_file(pub_file, pub_b64) != OK ||
        write_text_file(priv_file, priv_b64) != OK) {
        free(pub_b64);
        free(priv_b64);
        return ERROR;
    }

    printf(" ----------------------------------------------------------------------\n");
    printf(" [✓] Llave Pública (Base64) guardada en : '%s' (%zu chars)\n", pub_file, strlen(pub_b64));
    printf("     Vista previa: %.64s...\n", pub_b64);
    printf(" [✓] Llave Privada CRT (Base64) en      : '%s' (%zu chars)\n", priv_file, strlen(priv_b64));
    printf("     Vista previa: %.64s...\n", priv_b64);
    printf("======================================================================\n\n");

    free(pub_b64);
    OPENSSL_cleanse(priv_b64, strlen(priv_b64));
    free(priv_b64);
    return OK;
}

EVP_PKEY* oaep_load_public_key_b64(const char* pub_file) {
    char* b64 = read_text_file(pub_file);
    if (!b64) return NULL;

    // Si tiene cabeceras PEM, usar PEM_read_PUBKEY
    if (strstr(b64, "-----BEGIN")) {
        free(b64);
        FILE* fp = fopen(pub_file, "r");
        if (!fp) return NULL;
        EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
        return pkey;
    }

    size_t der_len = 0;
    unsigned char* der = base64_decode(b64, &der_len);
    free(b64);
    if (!der) return NULL;

    const unsigned char* p = der;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, (long)der_len);
    free(der);
    return pkey;
}

EVP_PKEY* oaep_load_private_key_b64(const char* priv_file) {
    char* b64 = read_text_file(priv_file);
    if (!b64) return NULL;

    if (strstr(b64, "-----BEGIN")) {
        free(b64);
        FILE* fp = fopen(priv_file, "r");
        if (!fp) return NULL;
        EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        return pkey;
    }

    size_t der_len = 0;
    unsigned char* der = base64_decode(b64, &der_len);
    OPENSSL_cleanse(b64, strlen(b64));
    free(b64);
    if (!der) return NULL;

    const unsigned char* p = der;
    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, (long)der_len);
    OPENSSL_cleanse(der, der_len);
    free(der);
    return pkey;
}

// -----------------------------------------------------------------------------
// Ejercicio 2.2: Generar llave K aleatoria de 128 bits para AES en Base64
// y cifrar/descifrar cualquier archivo usando AES-128 plano (sin CTR)
// -----------------------------------------------------------------------------

int aes128_generate_key(unsigned char key[AES_128_KEY_BYTES], char** out_b64) {
    if (RAND_bytes(key, AES_128_KEY_BYTES) != 1) {
        fprintf(stderr, "[-] Error al generar 128 bits de entropía para la llave AES K.\n");
        return ERROR;
    }
    char* b64 = base64_encode(key, AES_128_KEY_BYTES);
    if (!b64) return ERROR;

    printf("\n======================================================================\n");
    printf("         EJERCICIO 2.2: GENERACIÓN DE LLAVE SIMÉTRICA AES-128         \n");
    printf("======================================================================\n");
    printf(" Longitud de K        : 128 bits (16 bytes)\n");
    printf(" Llave K (Hex)        : ");
    for (int i = 0; i < AES_128_KEY_BYTES; i++) printf("%02x", key[i]);
    printf("\n");
    printf(" Llave K (Base64)     : %s\n", b64);
    printf("======================================================================\n\n");

    if (out_b64) {
        *out_b64 = b64;
    } else {
        free(b64);
    }
    return OK;
}

/*
 * Cifrado AES-128 "plano": cada bloque de 16 bytes se cifra de forma independiente
 * con la primitiva AES (FIPS 197) usando únicamente la llave K, sin contador ni IV
 * (modo ECB en terminología de NIST SP 800-38A). El último bloque se completa con
 * relleno PKCS#7 para soportar archivos de cualquier tamaño.
 *
 * Formato de salida:
 *   - Con cabecera: MAGIC_AESC (4 bytes "AESC") || C_1 || C_2 || ... || C_k
 *   - Modo crudo / raw: C_1 || C_2 || ... || C_k
 */
int aes128_encrypt_file_ex(
    const char* in_file,
    const char* out_file,
    const unsigned char key[AES_128_KEY_BYTES],
    bool write_header
) {
    FILE* fin = fopen(in_file, "rb");
    if (!fin) {
        fprintf(stderr, "[-] Error al abrir archivo de entrada para AES: '%s'\n", in_file);
        return ERROR;
    }
    FILE* fout = fopen(out_file, "wb");
    if (!fout) {
        fprintf(stderr, "[-] Error al crear archivo cifrado AES: '%s'\n", out_file);
        fclose(fin);
        return ERROR;
    }

    if (write_header) {
        uint32_t magic = MAGIC_AESC;
        fwrite(&magic, sizeof(uint32_t), 1, fout);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // AES-128 por bloques independientes: sin IV (NULL), relleno PKCS#7 habilitado
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return ERROR;
    }

    unsigned char in_buf[8192];
    unsigned char out_buf[8192 + EVP_MAX_BLOCK_LENGTH];
    size_t nread = 0;
    int out_len = 0;
    size_t total_in = 0, total_out = 0;

    while ((nread = fread(in_buf, 1, sizeof(in_buf), fin)) > 0) {
        total_in += nread;
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)nread) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin); fclose(fout);
            return ERROR;
        }
        fwrite(out_buf, 1, (size_t)out_len, fout);
        total_out += (size_t)out_len;
    }

    // Último bloque con relleno PKCS#7
    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return ERROR;
    }
    if (out_len > 0) {
        fwrite(out_buf, 1, (size_t)out_len, fout);
        total_out += (size_t)out_len;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    size_t total_file_bytes = total_out + (write_header ? sizeof(uint32_t) : 0);
    printf("[✓] Archivo cifrado con AES-128 (bloques de 16 bytes, sin CTR/IV) exitosamente:\n");
    printf("    Entrada : '%s' (%zu bytes)\n", in_file, total_in);
    if (write_header) {
        printf("    Salida  : '%s' (%zu bytes = %zu bloques AES + 4 bytes cabecera AESC)\n\n",
               out_file, total_file_bytes, total_out / 16);
    } else {
        printf("    Salida  : '%s' (%zu bytes = %zu bloques AES, modo crudo sin cabecera)\n\n",
               out_file, total_file_bytes, total_out / 16);
    }
    return OK;
}

int aes128_encrypt_file(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]) {
    return aes128_encrypt_file_ex(in_file, out_file, key, true);
}

int aes128_encrypt_file_raw(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]) {
    return aes128_encrypt_file_ex(in_file, out_file, key, false);
}

/*
 * Descifrado AES-128 plano:
 * Si ignore_header es true, descifra directamente desde el byte 0 (modo crudo/raw).
 * Si ignore_header es false, verifica la cabecera mágica MAGIC_AESC ("AESC").
 * Si la cabecera está presente se consume; si no está presente, auto-detecta
 * ciphertext crudo, emite aviso y rebobina a byte 0 para permitir compatibilidad total.
 */
int aes128_decrypt_file_ex(
    const char* in_file,
    const char* out_file,
    const unsigned char key[AES_128_KEY_BYTES],
    bool ignore_header
) {
    FILE* fin = fopen(in_file, "rb");
    if (!fin) {
        fprintf(stderr, "[-] Error al abrir archivo cifrado AES: '%s'\n", in_file);
        return ERROR;
    }

    if (ignore_header) {
        printf("[i] Modo ignorar cabecera activado (--ignore-header): leyendo ciphertext AES directamente desde byte 0.\n");
        fseek(fin, 0, SEEK_SET);
    } else {
        uint32_t magic = 0;
        size_t n = fread(&magic, sizeof(uint32_t), 1, fin);
        if (n == 1 && magic == MAGIC_AESC) {
            printf("[i] Cabecera mágica 'AESC' verificada (4 bytes).\n");
        } else {
            printf("[!] Advertencia: Cabecera 'AESC' no detectada en '%s'.\n", in_file);
            printf("[i] Auto-detección: Rebobinando a byte 0 para descifrar como ciphertext AES crudo (sin cabecera)...\n");
            fseek(fin, 0, SEEK_SET);
        }
    }

    FILE* fout = fopen(out_file, "wb");
    if (!fout) {
        fprintf(stderr, "[-] Error al abrir archivo de salida: '%s'\n", out_file);
        fclose(fin);
        return ERROR;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // Descifrado AES-128 plano: P_i = AES^-1_K(C_i), sin IV
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return ERROR;
    }

    unsigned char in_buf[8192];
    unsigned char out_buf[8192 + EVP_MAX_BLOCK_LENGTH];
    size_t nread = 0;
    int out_len = 0;
    size_t total_out = 0;

    while ((nread = fread(in_buf, 1, sizeof(in_buf), fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, (int)nread) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin); fclose(fout);
            return ERROR;
        }
        fwrite(out_buf, 1, (size_t)out_len, fout);
        total_out += (size_t)out_len;
    }

    // Verifica y retira el relleno PKCS#7 (falla si la llave K es incorrecta)
    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        fprintf(stderr, "[-] Error: relleno PKCS#7 inválido (llave K incorrecta o archivo dañado).\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return ERROR;
    }
    if (out_len > 0) {
        fwrite(out_buf, 1, (size_t)out_len, fout);
        total_out += (size_t)out_len;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);

    printf("[✓] Archivo descifrado con AES-128 (sin CTR/IV) exitosamente:\n");
    printf("    Archivo cifrado    : '%s'\n", in_file);
    printf("    Archivo recuperado : '%s' (%zu bytes)\n\n", out_file, total_out);
    return OK;
}

int aes128_decrypt_file(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]) {
    return aes128_decrypt_file_ex(in_file, out_file, key, false);
}

int aes128_decrypt_file_raw(const char* in_file, const char* out_file, const unsigned char key[AES_128_KEY_BYTES]) {
    return aes128_decrypt_file_ex(in_file, out_file, key, true);
}

// -----------------------------------------------------------------------------
// Ejercicio 2.3: Cifrar la llave K usando la llave pública para RSA-OAEP
// y almacenar la llave cifrada K en un archivo en Base64 elegido por el usuario
// -----------------------------------------------------------------------------

int rsa_oaep_encrypt_key_to_file(
    const char* pub_key_file,
    const unsigned char* k_bytes,
    size_t k_len,
    const char* out_enc_key_file
) {
    EVP_PKEY* pub_key = oaep_load_public_key_b64(pub_key_file);
    if (!pub_key) {
        fprintf(stderr, "[-] Error al cargar la llave pública RSA-OAEP desde '%s'.\n", pub_key_file);
        return ERROR;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(pub_key);
        return ERROR;
    }

    // Configuración conforme a NIST SP 800-56B Rev. 2 Sección 7.2.2.3 (RSA-OAEP.ENCRYPT)
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        return ERROR;
    }

    size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, k_bytes, k_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        return ERROR;
    }

    unsigned char* enc_buf = (unsigned char*)malloc(out_len);
    if (!enc_buf) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        return ERROR;
    }

    if (EVP_PKEY_encrypt(ctx, enc_buf, &out_len, k_bytes, k_len) <= 0) {
        free(enc_buf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        return ERROR;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);

    char* enc_b64 = base64_encode(enc_buf, out_len);
    free(enc_buf);
    if (!enc_b64) return ERROR;

    if (write_text_file(out_enc_key_file, enc_b64) != OK) {
        free(enc_b64);
        return ERROR;
    }

    printf("\n======================================================================\n");
    printf("     EJERCICIO 2.3: ENCAPSULAMIENTO DE LLAVE K CON RSA-OAEP           \n");
    printf("======================================================================\n");
    printf(" Llave pública usada        : '%s'\n", pub_key_file);
    printf(" Esquema de Padding         : RSA-PKCS1-OAEP (SHA-256 / MGF1-SHA256)\n");
    printf(" Tamaño del Ciphertext C    : %zu bytes (%zu bits)\n", out_len, out_len * 8);
    printf(" Archivo de salida (Base64) : '%s'\n", out_enc_key_file);
    printf(" Llave K Cifrada (Base64)   :\n   %.72s...\n", enc_b64);
    printf("======================================================================\n\n");

    free(enc_b64);
    return OK;
}

// -----------------------------------------------------------------------------
// Ejercicio 2.4: Descifrar la llave K cifrada usando la llave privada
// para RSA-OAEP con CRT e imprimir la llave K descifrada en Base64
// -----------------------------------------------------------------------------

int rsa_oaep_decrypt_key_from_file(
    const char* priv_key_file,
    const char* in_enc_key_file,
    unsigned char** out_k_bytes,
    size_t* out_k_len
) {
    EVP_PKEY* priv_key = oaep_load_private_key_b64(priv_key_file);
    if (!priv_key) {
        fprintf(stderr, "[-] Error al cargar la llave privada RSA-OAEP con CRT desde '%s'.\n", priv_key_file);
        return ERROR;
    }

    char* enc_b64 = read_text_file(in_enc_key_file);
    if (!enc_b64) {
        EVP_PKEY_free(priv_key);
        return ERROR;
    }

    size_t enc_len = 0;
    unsigned char* enc_buf = base64_decode(enc_b64, &enc_len);
    free(enc_b64);
    if (!enc_buf) {
        EVP_PKEY_free(priv_key);
        return ERROR;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        free(enc_buf);
        EVP_PKEY_free(priv_key);
        return ERROR;
    }

    // Configuración conforme a NIST SP 800-56B Rev. 2 Sección 7.2.2.4 (RSA-OAEP.DECRYPT con CRT)
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        free(enc_buf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        return ERROR;
    }

    size_t dec_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &dec_len, enc_buf, enc_len) <= 0) {
        free(enc_buf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        fprintf(stderr, "[-] Error en RSA-OAEP.DECRYPT (dimensionamiento).\n");
        return ERROR;
    }

    unsigned char* dec_buf = (unsigned char*)malloc(dec_len);
    if (!dec_buf) {
        free(enc_buf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        return ERROR;
    }

    if (EVP_PKEY_decrypt(ctx, dec_buf, &dec_len, enc_buf, enc_len) <= 0) {
        free(enc_buf);
        free(dec_buf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        fprintf(stderr, "[-] Error de descifrado RSA-OAEP (posible corrupción de padding o llave incorrecta).\n");
        return ERROR;
    }

    free(enc_buf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);

    char* k_b64 = base64_encode(dec_buf, dec_len);
    if (!k_b64) {
        OPENSSL_cleanse(dec_buf, dec_len);
        free(dec_buf);
        return ERROR;
    }

    printf("\n======================================================================\n");
    printf("   EJERCICIO 2.4: DESENCAPSULAMIENTO DE LLAVE K CON RSA-OAEP Y CRT    \n");
    printf("======================================================================\n");
    printf(" Llave privada CRT usada     : '%s'\n", priv_key_file);
    printf(" Archivo K cifrada (Base64)  : '%s'\n", in_enc_key_file);
    printf(" Longitud de K recuperada    : %zu bytes (%zu bits)\n", dec_len, dec_len * 8);
    printf(" Llave K Recuperada (Hex)    : ");
    for (size_t i = 0; i < dec_len; i++) printf("%02x", dec_buf[i]);
    printf("\n");
    printf(" Llave K Recuperada (Base64) : %s\n", k_b64);
    printf("======================================================================\n\n");

    free(k_b64);

    if (out_k_bytes && out_k_len) {
        *out_k_bytes = dec_buf;
        *out_k_len = dec_len;
    } else {
        OPENSSL_cleanse(dec_buf, dec_len);
        free(dec_buf);
    }
    return OK;
}

// -----------------------------------------------------------------------------
// Ejercicio 2.5: Prueba Integral del Protocolo KTS-OAEP (Alice y Bob)
// -----------------------------------------------------------------------------

static void print_file_sha256(const char* label, const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(mdctx, buf, n);
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hlen = 0;
    EVP_DigestFinal_ex(mdctx, hash, &hlen);
    EVP_MD_CTX_free(mdctx);
    fclose(f);

    printf("   %s (%s):\n     SHA-256 = ", label, filepath);
    for (unsigned int i = 0; i < hlen; i++) printf("%02x", hash[i]);
    printf("\n");
}

int run_alice_bob_oaep_simulation(
    int rsa_bits,
    const char* alice_pub_file,
    const char* alice_priv_file,
    const char* plain_file,
    const char* cipher_file,
    const char* enc_key_file,
    const char* recovered_file
) {
    printf("\n╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║   EJERCICIO 2.5: SIMULACIÓN PROTOCOLO KTS-OAEP + AES-128 (ALICE/BOB)     ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\n\n");

    // Crear un archivo de prueba si no existe plain_file
    struct stat st;
    if (stat(plain_file, &st) != 0) {
        FILE* f = fopen(plain_file, "w");
        if (f) {
            fprintf(f, "INSTITUTO POLITECNICO NACIONAL - ESCOM\n");
            fprintf(f, "Selected Topics in Cryptography - Lab 06: CTR and RSA-OAEP\n");
            fprintf(f, "Documento confidencial transmitido de Bob (Party U) a Alice (Party V)\n");
            fprintf(f, "mediante transporte de llave KTS-OAEP (NIST SP 800-56B Rev. 2) y AES-128.\n");
            fclose(f);
        }
    }

    // PASO 1: Alice genera su par de llaves RSA-OAEP con CRT en Base64 y comparte su llave pública con Bob
    printf(">>> [PASO 1 - ALICE] Generando par de llaves RSA-OAEP con CRT (%d bits)...\n", rsa_bits);
    if (oaep_generate_keypair_files(rsa_bits, alice_pub_file, alice_priv_file) != OK) {
        return ERROR;
    }
    printf("    -> Alice comparte '%s' (Base64) con Bob.\n\n", alice_pub_file);

    // PASO 2: Bob genera una llave aleatoria K de 128 bits para AES y la imprime en Base64
    printf(">>> [PASO 2 - BOB] Generando llave aleatoria K de 128 bits para AES-128...\n");
    unsigned char bob_k[AES_128_KEY_BYTES];
    char* bob_k_b64 = NULL;
    if (aes128_generate_key(bob_k, &bob_k_b64) != OK) {
        return ERROR;
    }

    // Bob cifra el archivo m usando K y AES-128
    printf(">>> [PASO 3 - BOB] Cifrando archivo '%s' con llave K y AES-128...\n", plain_file);
    if (aes128_encrypt_file(plain_file, cipher_file, bob_k) != OK) {
        free(bob_k_b64);
        return ERROR;
    }

    // PASO 3: Bob cifra la llave K con RSA-OAEP usando la llave pública de Alice y la guarda en Base64
    printf(">>> [PASO 4 - BOB] Cifrando llave K con RSA-OAEP usando la llave pública de Alice ('%s')...\n", alice_pub_file);
    if (rsa_oaep_encrypt_key_to_file(alice_pub_file, bob_k, AES_128_KEY_BYTES, enc_key_file) != OK) {
        free(bob_k_b64);
        return ERROR;
    }
    printf("    -> Bob comparte la llave K cifrada ('%s') y el ciphertext ('%s') con Alice.\n\n",
           enc_key_file, cipher_file);

    // PASO 4: Alice descifra la llave K cifrada con su llave privada usando RSA-OAEP con CRT
    printf(">>> [PASO 5 - ALICE] Descifrando '%s' con su llave privada RSA-OAEP con CRT ('%s')...\n",
           enc_key_file, alice_priv_file);
    unsigned char* alice_k = NULL;
    size_t alice_k_len = 0;
    if (rsa_oaep_decrypt_key_from_file(alice_priv_file, enc_key_file, &alice_k, &alice_k_len) != OK) {
        free(bob_k_b64);
        return ERROR;
    }

    char* alice_k_b64 = base64_encode(alice_k, alice_k_len);
    printf(" [Verificación de Transporte de Llave KTS-OAEP]:\n");
    printf("   - K generada por Bob (Base64)     : %s\n", bob_k_b64);
    printf("   - K recuperada por Alice (Base64) : %s\n", alice_k_b64 ? alice_k_b64 : "");
    if (alice_k_len == AES_128_KEY_BYTES && memcmp(bob_k, alice_k, AES_128_KEY_BYTES) == 0) {
        printf("   -> [✓] ÉXITO: Alice recuperó exactamente la misma llave K de 128 bits.\n\n");
    } else {
        printf("   -> [✗] ERROR: Las llaves K no coinciden.\n\n");
        free(bob_k_b64);
        free(alice_k_b64);
        free(alice_k);
        return ERROR;
    }

    // Una vez recuperada K, Alice descifra el ciphertext con AES-128
    printf(">>> [PASO 6 - ALICE] Descifrando el archivo '%s' con la llave K recuperada y AES-128...\n", cipher_file);
    if (aes128_decrypt_file(cipher_file, recovered_file, alice_k) != OK) {
        free(bob_k_b64);
        free(alice_k_b64);
        free(alice_k);
        return ERROR;
    }

    printf("======================================================================\n");
    printf("          VERIFICACIÓN DE INTEGRIDAD CRIPTOGRÁFICA (SHA-256)          \n");
    printf("======================================================================\n");
    print_file_sha256("Archivo Original de Bob   ", plain_file);
    print_file_sha256("Archivo Descifrado (Alice)", recovered_file);
    printf(" [✓] PROTOCOLO KTS-OAEP + AES-128 COMPLETADO EXITOSAMENTE AL 100%%\n");
    printf("======================================================================\n\n");

    OPENSSL_cleanse(bob_k, sizeof(bob_k));
    OPENSSL_cleanse(alice_k, alice_k_len);
    free(bob_k_b64);
    free(alice_k_b64);
    free(alice_k);
    return OK;
}

// =============================================================================
// INTERFAZ DE USUARIO CLI INTERACTIVA (SECCIÓN 1 + SECCIÓN 2)
// =============================================================================

void run_interactive_cli(void) {
    rsa_sc_t current_keys;
    rsa_keys_init(&current_keys);
    bool has_keys = false;

    unsigned char session_aes_key[AES_128_KEY_BYTES];
    bool has_aes_key = false;

    while (1) {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════════════╗\n");
        printf("║          SISTEMA CRIPTOGRÁFICO LAB 06: CTR Y RSA-OAEP CON CRT          ║\n");
        printf("╠════════════════════════════════════════════════════════════════════════╣\n");
        printf("║  --- SECCIÓN 1: SCHOOLBOOK RSA CON CRT (SIN LIBRERÍA CRIPTO, GMP) ---  ║\n");
        printf("║   1. Generar par de llaves escolar (p, q, n, d, dp, dq) y (e, n)       ║\n");
        printf("║   2. Guardar / Cargar llaves escolares en disco (.pub / .priv)         ║\n");
        printf("║   3. Cifrar un entero m (0 < m < n) usando exp_bin (Algoritmo 1)       ║\n");
        printf("║   4. Descifrar un entero c (0 < c < n) con CRT (Desglose paso a paso)  ║\n");
        printf("║   5. Cifrar / Descifrar archivo con RSA Escolar por bloques            ║\n");
        printf("║   6. Ejecutar Batería de Pruebas Sección 1 (5 llaves, 10 mensajes)     ║\n");
        printf("╠════════════════════════════════════════════════════════════════════════╣\n");
        printf("║  --- SECCIÓN 2: RSA-OAEP CON CRT Y AES-128 PLANO (OPENSSL EVP) ---     ║\n");
        printf("║   7. [Ej. 2.1] Generar par de llaves RSA-OAEP con CRT en Base64        ║\n");
        printf("║   8. [Ej. 2.2] Generar llave K (128 bits) en Base64 y cifrar con AES   ║\n");
        printf("║   9. [Ej. 2.3] Cifrar llave K con llave pública RSA-OAEP (Base64)      ║\n");
        printf("║  10. [Ej. 2.4] Descifrar llave K con privada RSA-OAEP-CRT y descifrar  ║\n");
        printf("║  11. [Ej. 2.5] Ejecutar Simulación Completa Alice y Bob (KTS-OAEP)     ║\n");
        printf("║  12. Salir                                                             ║\n");
        printf("╚════════════════════════════════════════════════════════════════════════╝\n");
        printf("Seleccione una opción [1-12]: ");

        int op = 0;
        if (scanf("%d", &op) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');

        switch (op) {
            case 1: {
                size_t bits = 0;
                printf("\nIngrese el tamaño en bits para p y q (>= 4, ej. 16, 64, 256, 512): ");
                if (scanf("%zu", &bits) != 1 || bits < 4) {
                    printf("[-] Tamaño inválido. Debe ser >= 4.\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n');
                if (gen_key(&current_keys, bits) == OK) {
                    has_keys = true;
                    printf("[✓] Par de llaves RSA-CRT generado y almacenado en sesión.\n");
                }
                break;
            }
            case 2: {
                printf("¿Desea (1) Guardar llaves actuales o (2) Cargar llaves desde disco? [1/2]: ");
                int sub = 0;
                if (scanf("%d", &sub) != 1) { while (getchar() != '\n') {} break; }
                while (getchar() != '\n');
                char pub_path[256], priv_path[256];
                printf("Ruta de llave pública (ej. rsa_key.pub): ");
                if (fgets(pub_path, sizeof(pub_path), stdin)) pub_path[strcspn(pub_path, "\r\n")] = 0;
                printf("Ruta de llave privada (ej. rsa_key.priv): ");
                if (fgets(priv_path, sizeof(priv_path), stdin)) priv_path[strcspn(priv_path, "\r\n")] = 0;
                if (sub == 1 && has_keys) {
                    rsa_save_pub_key(pub_path, &current_keys.pub);
                    rsa_save_priv_key(priv_path, &current_keys.priv);
                } else if (sub == 2) {
                    if (rsa_load_pub_key(pub_path, &current_keys.pub) == OK &&
                        rsa_load_priv_key(priv_path, &current_keys.priv) == OK) {
                        has_keys = true;
                    }
                } else {
                    printf("[-] Genere una llave primero.\n");
                }
                break;
            }
            case 3: {
                if (!has_keys) {
                    printf("[-] Cargue o genere una llave escolar primero (Opción 1 o 2).\n");
                    break;
                }
                char m_str[4096];
                printf("Ingrese el entero a cifrar m (0 < m < n): ");
                if (fgets(m_str, sizeof(m_str), stdin)) {
                    m_str[strcspn(m_str, "\r\n")] = 0;
                    mpz_t m, c;
                    mpz_inits(m, c, NULL);
                    if (mpz_set_str(m, m_str, 10) == 0) {
                        rsa_encrypt_int(c, &current_keys.pub, m);
                    }
                    mpz_clears(m, c, NULL);
                }
                break;
            }
            case 4: {
                if (!has_keys) {
                    printf("[-] Cargue o genere una llave escolar primero (Opción 1 o 2).\n");
                    break;
                }
                char c_str[4096];
                printf("Ingrese el ciphertext entero c a descifrar (0 < c < n): ");
                if (fgets(c_str, sizeof(c_str), stdin)) {
                    c_str[strcspn(c_str, "\r\n")] = 0;
                    mpz_t c, m;
                    mpz_inits(c, m, NULL);
                    if (mpz_set_str(c, c_str, 10) == 0) {
                        rsa_decrypt_int(m, &current_keys.priv, c);
                    }
                    mpz_clears(c, m, NULL);
                }
                break;
            }
            case 5: {
                if (!has_keys) {
                    printf("[-] Cargue o genere una llave escolar primero.\n");
                    break;
                }
                printf("¿Desea (1) Cifrar archivo o (2) Descifrar archivo con CRT? [1/2]: ");
                int sub = 0;
                if (scanf("%d", &sub) != 1) { while (getchar() != '\n') {} break; }
                while (getchar() != '\n');
                char in_p[256], out_p[256];
                printf("Archivo de entrada: ");
                if (fgets(in_p, sizeof(in_p), stdin)) in_p[strcspn(in_p, "\r\n")] = 0;
                printf("Archivo de salida: ");
                if (fgets(out_p, sizeof(out_p), stdin)) out_p[strcspn(out_p, "\r\n")] = 0;
                if (sub == 1) rsa_encrypt(in_p, out_p, current_keys.pub);
                else if (sub == 2) rsa_decrypt(in_p, out_p, current_keys.priv);
                break;
            }
            case 6:
                run_automated_tests();
                break;
            case 7: {
                int bits = DEFAULT_OAEP_BITS;
                char pub_f[256], priv_f[256];
                printf("Longitud del módulo RSA en bits (ej. 2048, 3072, 4096) [default 3072]: ");
                char b_str[64];
                if (fgets(b_str, sizeof(b_str), stdin)) {
                    int v = atoi(b_str);
                    if (v >= 1024) bits = v;
                }
                printf("Nombre de archivo para la llave pública en Base64 (ej. alice_pub.b64): ");
                if (fgets(pub_f, sizeof(pub_f), stdin)) pub_f[strcspn(pub_f, "\r\n")] = 0;
                printf("Nombre de archivo para la llave privada en Base64 (ej. alice_priv.b64): ");
                if (fgets(priv_f, sizeof(priv_f), stdin)) priv_f[strcspn(priv_f, "\r\n")] = 0;
                oaep_generate_keypair_files(bits, pub_f, priv_f);
                break;
            }
            case 8: {
                char* k_b64 = NULL;
                if (aes128_generate_key(session_aes_key, &k_b64) == OK) {
                    has_aes_key = true;
                    free(k_b64);
                    char in_f[256], out_f[256];
                    printf("Archivo a cifrar con K y AES-128 (ej. documento.pdf): ");
                    if (fgets(in_f, sizeof(in_f), stdin)) in_f[strcspn(in_f, "\r\n")] = 0;
                    printf("Archivo de salida cifrado (ej. documento.aes.enc): ");
                    if (fgets(out_f, sizeof(out_f), stdin)) out_f[strcspn(out_f, "\r\n")] = 0;
                    char opt_hdr[16] = "";
                    printf("¿Incluir cabecera mágica 'AESC' de 4 bytes? [S/n]: ");
                    if (fgets(opt_hdr, sizeof(opt_hdr), stdin)) opt_hdr[strcspn(opt_hdr, "\r\n")] = 0;
                    bool write_hdr = !(opt_hdr[0] == 'n' || opt_hdr[0] == 'N');
                    if (strlen(in_f) > 0 && strlen(out_f) > 0) {
                        aes128_encrypt_file_ex(in_f, out_f, session_aes_key, write_hdr);
                    }
                }
                break;
            }
            case 9: {
                if (!has_aes_key) {
                    printf("[*] Generando llave K de 128 bits automáticamente...\n");
                    aes128_generate_key(session_aes_key, NULL);
                    has_aes_key = true;
                }
                char pub_f[256], out_ekey[256];
                printf("Archivo de llave pública RSA-OAEP en Base64 (ej. alice_pub.b64): ");
                if (fgets(pub_f, sizeof(pub_f), stdin)) pub_f[strcspn(pub_f, "\r\n")] = 0;
                printf("Nombre de archivo donde guardar K cifrada en Base64 (ej. enc_k.b64): ");
                if (fgets(out_ekey, sizeof(out_ekey), stdin)) out_ekey[strcspn(out_ekey, "\r\n")] = 0;
                rsa_oaep_encrypt_key_to_file(pub_f, session_aes_key, AES_128_KEY_BYTES, out_ekey);
                break;
            }
            case 10: {
                char priv_f[256], in_ekey[256], in_enc[256], out_dec[256];
                printf("Archivo de llave privada RSA-OAEP con CRT en Base64 (ej. alice_priv.b64): ");
                if (fgets(priv_f, sizeof(priv_f), stdin)) priv_f[strcspn(priv_f, "\r\n")] = 0;
                printf("Archivo con la llave K cifrada en Base64 (ej. enc_k.b64): ");
                if (fgets(in_ekey, sizeof(in_ekey), stdin)) in_ekey[strcspn(in_ekey, "\r\n")] = 0;

                unsigned char* rec_k = NULL;
                size_t rec_k_len = 0;
                if (rsa_oaep_decrypt_key_from_file(priv_f, in_ekey, &rec_k, &rec_k_len) == OK) {
                    if (rec_k_len == AES_128_KEY_BYTES) {
                        memcpy(session_aes_key, rec_k, AES_128_KEY_BYTES);
                        has_aes_key = true;
                        printf("Archivo cifrado con AES-128 a descifrar (Enter para omitir): ");
                        if (fgets(in_enc, sizeof(in_enc), stdin)) in_enc[strcspn(in_enc, "\r\n")] = 0;
                        if (strlen(in_enc) > 0) {
                            printf("Archivo de salida recuperado: ");
                            if (fgets(out_dec, sizeof(out_dec), stdin)) out_dec[strcspn(out_dec, "\r\n")] = 0;
                            char ign_opt[32] = "";
                            printf("¿Ignorar cabecera 'AESC' (forzar modo crudo/raw desde byte 0)? [s/N]: ");
                            if (fgets(ign_opt, sizeof(ign_opt), stdin)) ign_opt[strcspn(ign_opt, "\r\n")] = 0;
                            bool ign = (ign_opt[0] == 's' || ign_opt[0] == 'S' || ign_opt[0] == 'y' || ign_opt[0] == 'Y');
                            aes128_decrypt_file_ex(in_enc, out_dec, session_aes_key, ign);
                        }
                    }
                    OPENSSL_cleanse(rec_k, rec_k_len);
                    free(rec_k);
                }
                break;
            }
            case 11: {
                char pub_f[256], priv_f[256], plain_f[256], cip_f[256], ekey_f[256], rec_f[256];
                printf("Archivo llave pública de Alice [default: alice_oaep_pub.b64]: ");
                if (fgets(pub_f, sizeof(pub_f), stdin)) pub_f[strcspn(pub_f, "\r\n")] = 0;
                if (strlen(pub_f) == 0) strcpy(pub_f, "alice_oaep_pub.b64");

                printf("Archivo llave privada CRT de Alice [default: alice_oaep_priv.b64]: ");
                if (fgets(priv_f, sizeof(priv_f), stdin)) priv_f[strcspn(priv_f, "\r\n")] = 0;
                if (strlen(priv_f) == 0) strcpy(priv_f, "alice_oaep_priv.b64");

                printf("Archivo en claro de Bob a cifrar [default: mensaje_bob.txt]: ");
                if (fgets(plain_f, sizeof(plain_f), stdin)) plain_f[strcspn(plain_f, "\r\n")] = 0;
                if (strlen(plain_f) == 0) strcpy(plain_f, "mensaje_bob.txt");

                printf("Archivo cifrado con AES-128 [default: mensaje_bob.aes.enc]: ");
                if (fgets(cip_f, sizeof(cip_f), stdin)) cip_f[strcspn(cip_f, "\r\n")] = 0;
                if (strlen(cip_f) == 0) strcpy(cip_f, "mensaje_bob.aes.enc");

                printf("Archivo llave K cifrada con RSA-OAEP [default: llave_k_oaep.b64]: ");
                if (fgets(ekey_f, sizeof(ekey_f), stdin)) ekey_f[strcspn(ekey_f, "\r\n")] = 0;
                if (strlen(ekey_f) == 0) strcpy(ekey_f, "llave_k_oaep.b64");

                printf("Archivo recuperado por Alice [default: mensaje_alice_recuperado.txt]: ");
                if (fgets(rec_f, sizeof(rec_f), stdin)) rec_f[strcspn(rec_f, "\r\n")] = 0;
                if (strlen(rec_f) == 0) strcpy(rec_f, "mensaje_alice_recuperado.txt");

                run_alice_bob_oaep_simulation(DEFAULT_OAEP_BITS, pub_f, priv_f, plain_f, cip_f, ekey_f, rec_f);
                break;
            }
            case 12:
                printf("\nSaliendo del programa. ¡Hasta pronto!\n");
                rsa_keys_clear(&current_keys);
                OPENSSL_cleanse(session_aes_key, sizeof(session_aes_key));
                return;
            default:
                printf("[-] Opción no válida.\n");
                break;
        }
    }
}
