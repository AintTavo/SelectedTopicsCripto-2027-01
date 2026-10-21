#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <gmp.h>

// -----------------------------------------------------------------------------
// Definición de constantes y códigos de retorno
// -----------------------------------------------------------------------------

#define OK      0
#define ERROR   1

#define MAGIC_RSAC 0x43415352 // "RSAC" en little-endian / byte stream

// -----------------------------------------------------------------------------
// Definición de estructuras de datos para Llaves RSA
// -----------------------------------------------------------------------------

/* Estructura para Llave Privada RSA con soporte para CRT */
typedef struct {
    mpz_t p;    /* Primer factor primo de n */
    mpz_t q;    /* Segundo factor primo de n */
    mpz_t n;    /* Módulo RSA: n = p * q */
    mpz_t d;    /* Exponente privado: d = e^(-1) mod phi(n) */
    mpz_t d_p;  /* Exponente CRT para p: d_p = d mod (p - 1) */
    mpz_t d_q;  /* Exponente CRT para q: d_q = d mod (q - 1) */
} rsa_sc_pri_key_t;

/* Estructura para Llave Pública RSA */
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
// Prototipos de funciones
// -----------------------------------------------------------------------------

/* Inicialización y liberación de memoria GMP */
void rsa_pub_init(rsa_sc_pub_key_t* pub);
void rsa_pub_clear(rsa_sc_pub_key_t* pub);
void rsa_priv_init(rsa_sc_pri_key_t* priv);
void rsa_priv_clear(rsa_sc_pri_key_t* priv);
void rsa_keys_init(rsa_sc_t* keys);
void rsa_keys_clear(rsa_sc_t* keys);

/* Generación de entropía y llaves */
void init_gmp_rand(gmp_randstate_t state);
int gen_key(rsa_sc_t* out_keys, size_t bits);

/* Algoritmo 1: Square and Multiply */
int exp_bin(mpz_t rop, const mpz_t x, const mpz_t H, const mpz_t n);

/* Teorema Chino del Residuo (CRT) */
int ctr(mpz_t rop, const mpz_t c, const rsa_sc_pri_key_t* priv);

/* Cifrado y descifrado de enteros escolares (Ejercicios 3 y 4) */
int rsa_encrypt_int(mpz_t c, const rsa_sc_pub_key_t* pub, const mpz_t m);
int rsa_decrypt_int(mpz_t m, const rsa_sc_pri_key_t* priv, const mpz_t c);

/* Cifrado y descifrado de cualquier archivo en disco (Requisito solicitado) */
int rsa_encrypt(const char* in_filename, const char* out_filename, rsa_sc_pub_key_t pub);
int rsa_decrypt(const char* in_filename, const char* out_filename, rsa_sc_pri_key_t priv);

/* Persistencia en disco de llaves (Guardar / Cargar) */
int rsa_save_pub_key(const char* filepath, const rsa_sc_pub_key_t* pub);
int rsa_load_pub_key(const char* filepath, rsa_sc_pub_key_t* pub);
int rsa_save_priv_key(const char* filepath, const rsa_sc_pri_key_t* priv);
int rsa_load_priv_key(const char* filepath, rsa_sc_pri_key_t* priv);

/* Batería de pruebas automáticas (Ejercicio 6 de la práctica) */
int run_automated_tests(void);

/* Menú interactivo CLI */
void run_interactive_cli(void);

// -----------------------------------------------------------------------------
// MAIN: Permite modo interactivo por defecto o modo flags para scripting/test
// -----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--test") == 0) {
            return run_automated_tests();
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
            printf("Llaves generadas y guardadas en %s y %s\n", argv[3], argv[4]);
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
        } else {
            printf("Uso:\n");
            printf("  %s                   : Modo interactivo (Menú CLI)\n", argv[0]);
            printf("  %s --test            : Ejecutar prueba automatizada (Ejercicio 6)\n", argv[0]);
            printf("  %s --keygen <bits> <pub_file> <priv_file>\n", argv[0]);
            printf("  %s --encrypt-file <pub_file> <in_file> <out_file>\n", argv[0]);
            printf("  %s --decrypt-file <priv_file> <in_file> <out_file>\n", argv[0]);
            return ERROR;
        }
    }

    run_interactive_cli();
    return OK;
}

// -----------------------------------------------------------------------------
// Funciones de Inicialización y Limpieza de Memoria GMP
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Inicialización del generador aleatorio con entropía criptográfica real
// -----------------------------------------------------------------------------

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
// Ejercicio 1: Generador de Llaves RSA Escolar con CRT
// Reglas:
// - |p| = |q| >= 4 bits
// - n = p * q
// - d = e^(-1) mod phi(n)  [o lambda(n)]
// - dp = d mod (p - 1)
// - dq = d mod (q - 1)
// - e aleatorio (gcd(e, phi) == 1, e != 3, e != 2^16+1)
// - Usar función de números primos del lenguaje (mpz_nextprime de GMP)
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

    // 1. Generación del primo p (|p| = bits)
    do {
        mpz_urandomb(out_keys->priv.p, state, bits);
        mpz_setbit(out_keys->priv.p, bits - 1); // Garantiza bit más significativo
        mpz_setbit(out_keys->priv.p, 0);        // Garantiza que sea impar
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

    // Garantizamos p > q para convención estándar en CRT
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

    // 5. Exponente público e aleatorio
    // Condición: gcd(e, phi) == 1, 1 < e < phi, e != 3, e != 65537 (2^16+1)
    size_t phi_bits = mpz_sizeinbase(phi, 2);
    size_t e_bits = (phi_bits > 16) ? (phi_bits / 2 + 1) : (phi_bits - 1);
    if (e_bits < 4) e_bits = phi_bits - 1;
    if (e_bits < 3) e_bits = 3;

    int attempts = 0;
    while (1) {
        attempts++;
        if (phi_bits > 4) {
            mpz_urandomb(out_keys->pub.e, state, e_bits);
            mpz_setbit(out_keys->pub.e, 0); // Impar
            if (mpz_cmp_ui(out_keys->pub.e, 3) <= 0) {
                mpz_add_ui(out_keys->pub.e, out_keys->pub.e, 4);
            }
        } else {
            mpz_set_ui(out_keys->pub.e, 5);
        }

        // Exclusión explícita solicitada: NO USAR e = 3 NI e = 2^16 + 1
        if (mpz_cmp_ui(out_keys->pub.e, 3) == 0) continue;
        if (mpz_cmp_ui(out_keys->pub.e, 65537) == 0) continue;

        if (mpz_cmp_ui(out_keys->pub.e, 1) > 0 && mpz_cmp(out_keys->pub.e, phi) < 0) {
            mpz_gcd(tmp_gcd, out_keys->pub.e, phi);
            if (mpz_cmp_ui(tmp_gcd, 1) == 0) {
                break; // 'e' coprimo con phi(n) encontrado exitosamente
            }
        }

        // Búsqueda secuencial si se dificulta el muestreo aleatorio en tamaños chicos
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

    // Impresión de llaves tal como lo especifica el Ejercicio 1
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
// Ejercicio 2: Algoritmo 1: Square and Multiply(x, H, n)
//
// Entrada : H = (b_{t-1}, ..., b_1, b_0)_2 representación binaria de H
//           n >= 0 y 0 <= x < n
// Salida  : x^H mod n
//
// Análisis matemático:
// Si r se inicializa con r <- x, se procesa el bit más significativo b_{t-1}=1.
// Para obtener la potencia exacta x^H mod n, el ciclo itera desde i = t - 2
// descendiendo hasta 0. (Si iterara desde t-1 con r <- x, se elevaría y
// multiplicaría dos veces el MSB). De manera equivalente y para mayor
// generalidad con H = 0, se maneja el caso base.
// -----------------------------------------------------------------------------

int exp_bin(mpz_t rop, const mpz_t x, const mpz_t H, const mpz_t n) {
    if (mpz_cmp_ui(n, 0) <= 0) {
        return ERROR;
    }

    // Caso H = 0 -> x^0 mod n = 1 mod n
    if (mpz_cmp_ui(H, 0) == 0) {
        mpz_set_ui(rop, 1);
        mpz_mod(rop, rop, n);
        return OK;
    }

    size_t t = mpz_sizeinbase(H, 2);
    mpz_t r, x_red;
    mpz_inits(r, x_red, NULL);

    // Reducción inicial de la base: x mod n
    mpz_mod(x_red, x, n);

    // Paso 1: r <- x mod n (Representa haber procesado el bit b_{t-1} = 1)
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
// Ejercicio 4: Teorema Chino del Residuo (CRT)
// Descifrado optimizado con impresión obligatoria de todos los valores intermedios.
//
// Implementa:
// 1. mp = c^dp mod p (con exp_bin)
// 2. mq = c^dq mod q (con exp_bin)
// 3. qInv = q^(-1) mod p y pInv = p^(-1) mod q
// 4. h = ((mp - mq) * qInv) mod p (Fórmula de Garner, NIST SP 800-56B Sec 7.1.2.3)
// 5. m = mq + (q * h) mod n
//
// También verifica la formulación simétrica de Gauss:
//    m = (mp * q * qInv + mq * p * pInv) mod n
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

    // 5. Reconstrucción: m = m_q + (h * q)
    mpz_mul(tmp, h, priv->q);
    mpz_add(m_garner, mq, tmp);
    mpz_mod(m_garner, m_garner, priv->n);
    gmp_printf(" [Paso 5] Mensaje recuperado m (Algoritmo de Garner):\n");
    gmp_printf("          m = m_q + (h * q) = %Zd\n\n", m_garner);

    // Verificación comparativa con la fórmula de Gauss
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

// -----------------------------------------------------------------------------
// Versión silenciosa de CRT para cifrado/descifrado masivo de archivos
// -----------------------------------------------------------------------------

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
// Ejercicio 3: Cifrado RSA Escolar de un Entero (0 < m < n)
// -----------------------------------------------------------------------------

int rsa_encrypt_int(mpz_t c, const rsa_sc_pub_key_t* pub, const mpz_t m) {
    if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, pub->n) >= 0) {
        fprintf(stderr, "[-] Error: El mensaje debe cumplir la condición 0 < m < n.\n");
        return ERROR;
    }

    // Utiliza la implementación de Algorithm 1 (exp_bin)
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

// -----------------------------------------------------------------------------
// Ejercicio 4: Descifrado RSA Escolar de un Entero con CRT (0 < c < n)
// -----------------------------------------------------------------------------

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
// CIFRADO Y DESCIFRADO DE CUALQUIER TIPO DE ARCHIVO
// Permite cifrar texto, imágenes, pdfs, ejecutables, etc.
// Divide el archivo en bloques de tamaño (modulus_bytes - 1), garantizando
// matemáticamente que cada bloque m cumple estrictamente 0 <= m < n.
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

    // Tamaño del módulo n en bytes
    size_t n_bits = mpz_sizeinbase(pub.n, 2);
    size_t n_len = (n_bits + 7) / 8;
    if (n_len < 2) {
        fprintf(stderr, "[-] Error: Llave demasiado corta para cifrado de archivos (se requiere n >= 16 bits).\n");
        fclose(fin);
        fclose(fout);
        return ERROR;
    }

    // Tamaño del bloque en claro: n_len - 1 bytes para asegurar m < n
    size_t chunk_len = n_len - 1;

    // Obtener tamaño del archivo original
    fseek(fin, 0, SEEK_END);
    uint64_t file_size = (uint64_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);

    // Escribir cabecera del formato cifrado
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
        // Importar bytes del bloque a mpz_t m
        mpz_import(m, bytes_read, 1, 1, 1, 0, in_buf);

        // Cifrar con exp_bin: c = m^e mod n
        exp_bin(c, m, pub.e, pub.n);

        // Exportar c en bloque fijo de n_len bytes con padding de ceros iniciales
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

    size_t priv_n_len = (mpz_sizeinbase(priv.n, 2) + 7) / 8;
    if (priv_n_len != n_len) {
        fprintf(stderr, "[-] Advertencia/Error: La llave privada proporcionada (%zu bytes) no coincide con el archivo (%zu bytes).\n",
                priv_n_len, n_len);
    }

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
        // Determinar cuantos bytes reales corresponden a este bloque
        size_t cur_chunk = (remaining_bytes < (uint64_t)chunk_len) ? (size_t)remaining_bytes : chunk_len;

        // Importar bloque cifrado a mpz_t c
        mpz_import(c, n_len, 1, 1, 1, 0, in_buf);

        // Descifrado con Teorema Chino del Residuo (CRT)
        ctr_silent(m, c, &priv);

        // Exportar a out_buf con ceros a la izquierda si el entero m omitio ceros iniciales
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
// Persistencia de Llaves en Disco (Guardar y Cargar)
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
// Ejercicio 6: Batería de Pruebas Automáticas
// Genera 5 pares de llaves diferentes, cifra 10 mensajes distintos,
// descifra cada ciphertext con CRT y verifica la integridad total.
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
        // Distribuir mensajes entre los 5 pares de llaves
        int k_idx = m_idx % 5;
        mpz_t m, c, m_rec;
        mpz_inits(m, c, m_rec, NULL);

        mpz_set_str(m, sample_messages[m_idx], 10);
        // Aseguramos 0 < m < n
        mpz_mod(m, m, keys[k_idx].pub.n);
        if (mpz_cmp_ui(m, 0) == 0) mpz_set_ui(m, 2);

        printf("\n[Test %02d/10] Probando con Llave #%d (%zu bits n):\n",
               m_idx + 1, k_idx + 1, mpz_sizeinbase(keys[k_idx].pub.n, 2));
        gmp_printf("  - Mensaje claro m: %Zd\n", m);

        // Cifrado con exp_bin
        exp_bin(c, m, keys[k_idx].pub.e, keys[k_idx].pub.n);
        gmp_printf("  - Ciphertext c   : %Zd\n", c);

        // Descifrado con CRT (ctr)
        if (m_idx == 0 || m_idx == 4) {
            // Imprime desglose completo para ver los pasos CRT requeridos por ejercicio 4
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

// -----------------------------------------------------------------------------
// Interfaz de Usuario CLI Interactiva
// -----------------------------------------------------------------------------

void run_interactive_cli(void) {
    rsa_sc_t current_keys;
    rsa_keys_init(&current_keys);
    bool has_keys = false;

    while (1) {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║             SISTEMA CRIPTOGRÁFICO RSA CON CRT (LAB 06)             ║\n");
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║  1. Generar nuevo par de llaves (p, q, n, d, dp, dq) y (e, n)      ║\n");
        printf("║  2. Guardar llaves actuales a disco (.pub / .priv)                 ║\n");
        printf("║  3. Cargar llaves desde disco                                      ║\n");
        printf("║  4. Cifrar un entero m (0 < m < n) usando exp_bin (Algoritmo 1)   ║\n");
        printf("║  5. Descifrar un entero c (0 < c < n) con Teorema Chino del Residuo║\n");
        printf("║  6. Cifrar cualquier archivo (imagen, texto, PDF, etc.)            ║\n");
        printf("║  7. Descifrar un archivo con CRT                                   ║\n");
        printf("║  8. Ejecutar Batería de Pruebas (5 llaves, 10 mensajes)            ║\n");
        printf("║  9. Salir                                                          ║\n");
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        if (has_keys) {
            gmp_printf(" [Estado actual: Llave cargada en memoria, n = %zu bits]\n",
                       mpz_sizeinbase(current_keys.pub.n, 2));
        } else {
            printf(" [Estado actual: Sin llave cargada]\n");
        }
        printf("Seleccione una opción [1-9]: ");

        int op = 0;
        if (scanf("%d", &op) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n'); // Limpiar buffer stdin

        switch (op) {
            case 1: {
                size_t bits = 0;
                printf("\nIngrese el tamaño en bits para p y q (>= 4, ej. 16, 64, 256, 512, 1024): ");
                if (scanf("%zu", &bits) != 1 || bits < 4) {
                    printf("[-] Tamaño invalido. Debe ser >= 4.\n");
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
                if (!has_keys) {
                    printf("[-] No hay llaves generadas o cargadas en memoria.\n");
                    break;
                }
                char pub_path[256], priv_path[256];
                printf("Nombre/Ruta para llave pública (ej. rsa_key.pub): ");
                if (fgets(pub_path, sizeof(pub_path), stdin)) {
                    pub_path[strcspn(pub_path, "\r\n")] = 0;
                }
                printf("Nombre/Ruta para llave privada (ej. rsa_key.priv): ");
                if (fgets(priv_path, sizeof(priv_path), stdin)) {
                    priv_path[strcspn(priv_path, "\r\n")] = 0;
                }
                rsa_save_pub_key(pub_path, &current_keys.pub);
                rsa_save_priv_key(priv_path, &current_keys.priv);
                break;
            }
            case 3: {
                char pub_path[256], priv_path[256];
                printf("Ruta de la llave pública a cargar: ");
                if (fgets(pub_path, sizeof(pub_path), stdin)) pub_path[strcspn(pub_path, "\r\n")] = 0;
                printf("Ruta de la llave privada a cargar: ");
                if (fgets(priv_path, sizeof(priv_path), stdin)) priv_path[strcspn(priv_path, "\r\n")] = 0;

                int r1 = rsa_load_pub_key(pub_path, &current_keys.pub);
                int r2 = rsa_load_priv_key(priv_path, &current_keys.priv);
                if (r1 == OK && r2 == OK) {
                    has_keys = true;
                    printf("[✓] Ambas llaves cargadas exitosamente en memoria.\n");
                }
                break;
            }
            case 4: {
                if (!has_keys) {
                    printf("[-] Se requiere cargar o generar una llave pública primero.\n");
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
                    } else {
                        printf("[-] Error: Número entero decimal inválido.\n");
                    }
                    mpz_clears(m, c, NULL);
                }
                break;
            }
            case 5: {
                if (!has_keys) {
                    printf("[-] Se requiere cargar o generar una llave privada primero.\n");
                    break;
                }
                char c_str[4096];
                printf("Ingrese el ciphertext entero c a descifrar: ");
                if (fgets(c_str, sizeof(c_str), stdin)) {
                    c_str[strcspn(c_str, "\r\n")] = 0;
                    mpz_t c, m;
                    mpz_inits(c, m, NULL);
                    if (mpz_set_str(c, c_str, 10) == 0) {
                        rsa_decrypt_int(m, &current_keys.priv, c);
                    } else {
                        printf("[-] Error: Número entero decimal inválido.\n");
                    }
                    mpz_clears(c, m, NULL);
                }
                break;
            }
            case 6: {
                if (!has_keys) {
                    printf("[-] Se requiere una llave pública en memoria.\n");
                    break;
                }
                char in_path[256], out_path[256];
                printf("Archivo a cifrar (ej. foto.png, documento.pdf, datos.bin): ");
                if (fgets(in_path, sizeof(in_path), stdin)) in_path[strcspn(in_path, "\r\n")] = 0;
                printf("Archivo de salida cifrado (ej. archivo.enc): ");
                if (fgets(out_path, sizeof(out_path), stdin)) out_path[strcspn(out_path, "\r\n")] = 0;

                rsa_encrypt(in_path, out_path, current_keys.pub);
                break;
            }
            case 7: {
                if (!has_keys) {
                    printf("[-] Se requiere una llave privada en memoria.\n");
                    break;
                }
                char in_path[256], out_path[256];
                printf("Archivo cifrado a descifrar (ej. archivo.enc): ");
                if (fgets(in_path, sizeof(in_path), stdin)) in_path[strcspn(in_path, "\r\n")] = 0;
                printf("Archivo de salida descifrado (ej. recuperado.png): ");
                if (fgets(out_path, sizeof(out_path), stdin)) out_path[strcspn(out_path, "\r\n")] = 0;

                rsa_decrypt(in_path, out_path, current_keys.priv);
                break;
            }
            case 8: {
                run_automated_tests();
                break;
            }
            case 9:
                printf("\nSaliendo del programa. ¡Hasta pronto!\n");
                rsa_keys_clear(&current_keys);
                return;
            default:
                printf("[-] Opción no válida.\n");
                break;
        }
    }
}
