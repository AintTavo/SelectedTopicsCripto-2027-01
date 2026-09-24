#include "ecdsa.h"
#include "ellipticcurve/elipt_curve.h"
#include <stdio.h>

int ecdsa_key_gen(keys_t* res, mpz_t p, mpz_t a, mpz_t b, point_t gen, mpz_t q){
    mpz_t d; 
    gmp_randstate_t state;
    mpz_init(d);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) ^ ((unsigned long)clock() << 16));

    // Seleccionar clave privada d en el rango [1, q - 1]
    do {
        mpz_urandomb(d, state, 512);
        mpz_mod(d, d, q);
    } while (mpz_cmp_ui(d, 0) == 0);
    
    point_t tmp_B, tmp_B_aff;
    point_init(&tmp_B);
    point_init(&tmp_B_aff);
    elipar_point_mul_l2r(&tmp_B, &gen, d, a, b, p, false);

    // Normalizar punto B a coordenadas afines canonicas (z = 1, o (0, 1, 0) si es infinito)
    if (point_is_infinity(&tmp_B)) {
        point_set_infinity(&tmp_B_aff);
    } else {
        elipar_projective_to_affine(&tmp_B_aff, &tmp_B, p);
    }

    // Llave privada
    mpz_init(res->keys_priv.kpriv_d);
    mpz_set(res->keys_priv.kpriv_d, d);

    // Llave publica en coordenadas afines canonicas (z = 1)
    mpz_inits(res->keys_pub.kpub_a, res->keys_pub.kpub_b, res->keys_pub.kpub_p, res->keys_pub.kpub_q, NULL);
    mpz_set(res->keys_pub.kpub_a, a);
    mpz_set(res->keys_pub.kpub_b, b);
    mpz_set(res->keys_pub.kpub_p, p);
    mpz_set(res->keys_pub.kpub_q, q);

    point_init(&res->keys_pub.kpub_A);
    point_init(&res->keys_pub.kpub_B);

    // Generador A en afines (z = 1)
    if (point_is_infinity(&gen)) {
        point_set_infinity(&res->keys_pub.kpub_A);
    } else {
        point_t gen_aff;
        point_init(&gen_aff);
        elipar_projective_to_affine(&gen_aff, &gen, p);
        point_set(&res->keys_pub.kpub_A, &gen_aff);
        point_clear(&gen_aff);
    }

    point_set(&res->keys_pub.kpub_B, &tmp_B_aff);

    point_clear(&tmp_B);
    point_clear(&tmp_B_aff);
    gmp_randclear(state);
    mpz_clear(d);
    return 0;
}

int ecdsa_signature(ecdsa_sign_t* res, kpriv_t key_priv, mpz_t p, point_t gen, mpz_t a, mpz_t b, mpz_t order, mpz_t hx){
    mpz_t key_e, tmp_s, tmp_r, tmp_inv_key_e;
    gmp_randstate_t state;
    point_t tmp_R, tmp_R_aff;
    
    mpz_inits(key_e, tmp_s, tmp_r, tmp_inv_key_e, res->sign_r, res->sign_s, NULL);
    point_init(&tmp_R);
    point_init(&tmp_R_aff);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) ^ ((unsigned long)clock() << 16) ^ 0x5deece66dUL);
    
    do {
        // Seleccionar nonce key_e en el rango [1, order - 1]
        do {
            mpz_urandomb(key_e, state, 512);
            mpz_mod(key_e, key_e, order);
        } while (mpz_cmp_ui(key_e, 0) == 0);
        
        // Computing r = (key_e * gen).x mod order
        elipar_point_mul_l2r(&tmp_R, &gen, key_e, a, b, p, false);
        elipar_projective_to_affine(&tmp_R_aff, &tmp_R, p);
        mpz_mod(tmp_r, tmp_R_aff.x, order);
        if (mpz_cmp_ui(tmp_r, 0) == 0) {
            continue;
        }
        
        // Computing s = key_e^(-1) * (hx + d * r) mod order
        if (mpz_invert(tmp_inv_key_e, key_e, order) == 0) {
            continue;
        }
        
        mpz_mul(tmp_s, key_priv.kpriv_d, tmp_r);
        mpz_mod(tmp_s, tmp_s, order);
        mpz_add(tmp_s, tmp_s, hx);
        mpz_mod(tmp_s, tmp_s, order);
        mpz_mul(tmp_s, tmp_s, tmp_inv_key_e);
        mpz_mod(tmp_s, tmp_s, order);
    } while (mpz_cmp_ui(tmp_s, 0) == 0);

    mpz_mod(tmp_s, tmp_s, order);
    mpz_mod(tmp_r, tmp_r, order);
    // Guardado de r y s
    mpz_set(res->sign_r, tmp_r);
    mpz_set(res->sign_s, tmp_s);
    
    mpz_clears(tmp_s, tmp_r, key_e, tmp_inv_key_e, NULL);
    gmp_randclear(state);
    point_clear(&tmp_R);
    point_clear(&tmp_R_aff);
    return 0;
}

int ecdsa_sign_verification(kpub_t key_pub, ecdsa_sign_t signature, mpz_t hx){
    int res = 0;

    // Verificacion de rango para r y s: r, s en [1, q - 1]
    if (mpz_cmp_ui(signature.sign_r, 1) < 0 || mpz_cmp(signature.sign_r, key_pub.kpub_q) >= 0 ||
        mpz_cmp_ui(signature.sign_s, 1) < 0 || mpz_cmp(signature.sign_s, key_pub.kpub_q) >= 0) {
        return 0;
    }

    mpz_t w, u1, u2;
    mpz_inits(w, u1, u2, NULL);

    if (mpz_invert(w, signature.sign_s, key_pub.kpub_q) == 0) {
        mpz_clears(w, u1, u2, NULL);
        return 0;
    }

    // Calculo de u1
    mpz_mul(u1, w, hx);
    mpz_mod(u1, u1, key_pub.kpub_q);

    // Calculo de u2
    mpz_mul(u2, w, signature.sign_r);
    mpz_mod(u2, u2, key_pub.kpub_q);

    // Calculo de P = u1 * A + u2 * B
    point_t tmp_P, tmp_A, tmp_B, tmp_P_aff;
    point_init(&tmp_P);
    point_init(&tmp_A);
    point_init(&tmp_B);
    point_init(&tmp_P_aff);

    elipar_point_mul_l2r(&tmp_A, &key_pub.kpub_A, u1, key_pub.kpub_a, key_pub.kpub_b, key_pub.kpub_p, false);
    elipar_point_mul_l2r(&tmp_B, &key_pub.kpub_B, u2, key_pub.kpub_a, key_pub.kpub_b, key_pub.kpub_p, false);

    elipar_point_add(&tmp_P, &tmp_A, &tmp_B, key_pub.kpub_a, key_pub.kpub_b, key_pub.kpub_p);

    if (!point_is_infinity(&tmp_P)) {
        elipar_projective_to_affine(&tmp_P_aff, &tmp_P, key_pub.kpub_p);
        mpz_t v;
        mpz_init(v);
        mpz_mod(v, tmp_P_aff.x, key_pub.kpub_q);

        if (mpz_cmp(v, signature.sign_r) == 0) {
            res = 1;
        }
        mpz_clear(v);
    }
    
    point_clear(&tmp_P_aff);
    point_clear(&tmp_P);
    point_clear(&tmp_A);
    point_clear(&tmp_B);
    mpz_clears(w, u1, u2, NULL);
    return res;
}

/* Funciones auxiliares de gestion de memoria */
void ecdsa_sign_init(ecdsa_sign_t* sig) {
    if (sig == NULL) return;
    mpz_inits(sig->sign_r, sig->sign_s, NULL);
}

void ecdsa_sign_clear(ecdsa_sign_t* sig) {
    if (sig == NULL) return;
    mpz_clears(sig->sign_r, sig->sign_s, NULL);
}

void ecdsa_kpub_init(kpub_t* pub) {
    if (pub == NULL) return;
    mpz_inits(pub->kpub_p, pub->kpub_a, pub->kpub_b, pub->kpub_q, NULL);
    point_init(&pub->kpub_A);
    point_init(&pub->kpub_B);
}

void ecdsa_kpub_clear(kpub_t* pub) {
    if (pub == NULL) return;
    mpz_clears(pub->kpub_p, pub->kpub_a, pub->kpub_b, pub->kpub_q, NULL);
    point_clear(&pub->kpub_A);
    point_clear(&pub->kpub_B);
}

void ecdsa_kpriv_init(kpriv_t* priv) {
    if (priv == NULL) return;
    mpz_init(priv->kpriv_d);
}

void ecdsa_kpriv_clear(kpriv_t* priv) {
    if (priv == NULL) return;
    mpz_clear(priv->kpriv_d);
}

void ecdsa_keys_init(keys_t* keys) {
    if (keys == NULL) return;
    ecdsa_kpriv_init(&keys->keys_priv);
    ecdsa_kpub_init(&keys->keys_pub);
}

void ecdsa_keys_clear(keys_t* keys) {
    if (keys == NULL) return;
    ecdsa_kpriv_clear(&keys->keys_priv);
    ecdsa_kpub_clear(&keys->keys_pub);
}