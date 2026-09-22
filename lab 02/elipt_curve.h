#ifndef ELIPT_CURVE_H
#define ELIPT_CURVE_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <gmp.h>

/*
 * Representacion de un punto en coordenadas de 3 dimensiones (x, y, z):
 * - Punto afin / normal: (x, y, 1) con z = 1
 * - Punto al infinito O: (0, 1, 0) con z = 0
 * Adaptado con la libreria GNU MP (GMP) para soportar enteros de longitud arbitraria.
 */
typedef struct {
    mpz_t x;
    mpz_t y;
    mpz_t z;
} point_t;

/* --- Gestion del ciclo de vida y operaciones basicas de point_t --- */
void point_init(point_t* p);
void point_clear(point_t* p);
void point_set(point_t* dest, const point_t* src);
void point_set_ui(point_t* p, unsigned long x, unsigned long y, unsigned long z);
void point_set_mpz(point_t* p, const mpz_t x, const mpz_t y, const mpz_t z);
void point_set_infinity(point_t* p);
bool point_is_infinity(const point_t* p);
int  point_cmp(const point_t* p1, const point_t* p2);
void point_print(const char* label, const point_t* p);
void elipar_free_points(point_t* points, size_t count);

/* --- Parser de expresiones numericas y formato de potencias ---
 * Soporta expresiones como: 65537, 2^31 - 1, 2^61 - 1, 2^255 - 19, (2^16) + 1, etc.
 */
int parse_mpz_expression(mpz_t rop, const char* str);
int read_mpz_from_input(mpz_t rop, const char* prompt_msg);

/* --- Estructuras para residuos cuadraticos (Seccion 1) --- */
typedef struct qr_entry {
    unsigned long key;            /* Residuo cuadratico */
    unsigned long roots[2];       /* Raices cuadradas asociadas */
    int root_count;               /* Cantidad de raices (1 para 0, 2 para r > 0) */
    bool is_occupied;             /* Ocupado en cubeta */
} qr_entry_t;

typedef struct qr_table {
    qr_entry_t* entries;          /* Cubetas indexadas por residuo */
    size_t capacity;              /* Capacidad de la tabla */
    size_t count;                 /* Total de residuos cuadraticos */
    unsigned long p;              /* Modulo primo */
} qr_table_t;

typedef qr_table_t qr_dict_t;

/* --- Seccion 1: Funciones preliminares --- */
qr_table_t* elipar_quadratic_residue(const mpz_t p);
const qr_entry_t* elipar_qr_lookup(const qr_table_t* table, unsigned long residue);
void elipar_qr_free(qr_table_t* table);

point_t* elipar_rational_points(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points);
point_t* elipar_rational(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points);
size_t   elipar_count_rational_points(const mpz_t a, const mpz_t b, const mpz_t p);
int      elipar_points_to_csv(const char* filename, const point_t* points, const size_t num_points, const mpz_t a, const mpz_t b, const mpz_t p);
int      elipar_is_in(const int a, const size_t len, const int* arr);

/* --- Verificaciones matematicas --- */
bool elipar_is_singular(const mpz_t a, const mpz_t b, const mpz_t p);
bool elipar_is_point_on_curve(const point_t* pt, const mpz_t a, const mpz_t b, const mpz_t p);

/* --- Seccion 2: Aritmetica de Curvas Elipticas (Enteros Grandes con GMP) --- */
/* Ejercicio 1: Recibe longitud n bits, genera primo aleatorio p de n bits y encuentra a, b de curva no-singular */
int elipar_generate_curve(mpz_t p, mpz_t a, mpz_t b, unsigned int n_bits, gmp_randstate_t state);

/* Ejercicio 2: Suma de puntos P + Q donde P != +-Q usando coordenadas proyectivas. */
int elipar_point_add(point_t* R, const point_t* P, const point_t* Q, const mpz_t a, const mpz_t b, const mpz_t p);

/* Ejercicio 3: Duplicacion de punto 2P usando coordenadas proyectivas. */
int elipar_point_double(point_t* R, const point_t* P, const mpz_t a, const mpz_t b, const mpz_t p);

/* Multiplicacion de puntos k*P usando el algoritmo double-and-add con coordenadas proyectivas. */
int elipar_point_mul_r2l(point_t* R, const point_t* P, const mpz_t k, const mpz_t a, const mpz_t b, const mpz_t p, bool print_steps);
int elipar_point_mul_l2r(point_t* R, const point_t* P, const mpz_t k, const mpz_t a, const mpz_t b, const mpz_t p, bool print_steps);

/* Convertir coordenadas proyectivas (X,Y,Z) a afines (X/Z, Y/Z, 1) */
int elipar_projective_to_affine(point_t* R, const point_t* P, const mpz_t p);

/* Firma ECDSA */
int elipar_ecdsa_sign(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, const point_t* G, const mpz_t d, const mpz_t e, const mpz_t k_nonce, mpz_t r, mpz_t s);

/* Verificacion ECDSA */
int elipar_ecdsa_verify(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, const point_t* G, const point_t* Q, const mpz_t e, const mpz_t r, const mpz_t s);

/* --- Seccion 3: Casos de prueba automatizados --- */
void elipar_run_section3_question2(void);
void elipar_run_section3_question3(void);

#endif /* ELIPT_CURVE_H */
