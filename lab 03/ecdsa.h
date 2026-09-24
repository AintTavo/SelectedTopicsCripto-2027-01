#ifndef ECDSA_H
#define ECDSA_H


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <gmp.h>

#include "ellipticcurve/elipt_curve.h"


typedef struct {
    mpz_t sign_r;
    mpz_t sign_s;
} ecdsa_sign_t;

typedef struct {
    mpz_t kpub_p;
    mpz_t kpub_a;
    mpz_t kpub_b;
    mpz_t kpub_q;
    point_t kpub_A;
    point_t kpub_B;
} kpub_t;

typedef struct {
    mpz_t kpriv_d;
} kpriv_t;

typedef struct {
    kpriv_t keys_priv;
    kpub_t keys_pub;
} keys_t;

int ecdsa_key_gen(keys_t* res, mpz_t p, mpz_t a, mpz_t b, point_t gen, mpz_t order);
int ecdsa_signature(ecdsa_sign_t* res, kpriv_t key_priv,mpz_t p, point_t gen, mpz_t a, mpz_t b, mpz_t order, mpz_t hx);
int ecdsa_sign_verification(kpub_t key_pub, ecdsa_sign_t signature, mpz_t hx);

/* Funciones auxiliares para inicializar y liberar estructuras ECDSA */
void ecdsa_sign_init(ecdsa_sign_t* sig);
void ecdsa_sign_clear(ecdsa_sign_t* sig);
void ecdsa_kpub_init(kpub_t* pub);
void ecdsa_kpub_clear(kpub_t* pub);
void ecdsa_kpriv_init(kpriv_t* priv);
void ecdsa_kpriv_clear(kpriv_t* priv);
void ecdsa_keys_init(keys_t* keys);
void ecdsa_keys_clear(keys_t* keys);

#endif