#include "elipt_curve.h"

/* =========================================================================
 * 1. GESTION DE MEMORIA Y PUNTOS (point_t) CON GMP
 * ========================================================================= */

void point_init(point_t* p) {
    if (p == NULL) return;
    mpz_inits(p->x, p->y, p->z, NULL);
}

void point_clear(point_t* p) {
    if (p == NULL) return;
    mpz_clears(p->x, p->y, p->z, NULL);
}

void point_set(point_t* dest, const point_t* src) {
    if (dest == NULL || src == NULL) return;
    mpz_set(dest->x, src->x);
    mpz_set(dest->y, src->y);
    mpz_set(dest->z, src->z);
}

void point_set_ui(point_t* p, unsigned long x, unsigned long y, unsigned long z) {
    if (p == NULL) return;
    mpz_set_ui(p->x, x);
    mpz_set_ui(p->y, y);
    mpz_set_ui(p->z, z);
}

void point_set_mpz(point_t* p, const mpz_t x, const mpz_t y, const mpz_t z) {
    if (p == NULL) return;
    mpz_set(p->x, x);
    mpz_set(p->y, y);
    mpz_set(p->z, z);
}

void point_set_infinity(point_t* p) {
    if (p == NULL) return;
    mpz_set_ui(p->x, 0);
    mpz_set_ui(p->y, 1);
    mpz_set_ui(p->z, 0);
}

bool point_is_infinity(const point_t* p) {
    if (p == NULL) return true;
    return (mpz_cmp_ui(p->z, 0) == 0);
}

int point_cmp(const point_t* p1, const point_t* p2) {
    if (p1 == NULL || p2 == NULL) return -1;
    if (point_is_infinity(p1) && point_is_infinity(p2)) return 0;
    if (point_is_infinity(p1) || point_is_infinity(p2)) return 1;
    if (mpz_cmp(p1->x, p2->x) == 0 &&
        mpz_cmp(p1->y, p2->y) == 0 &&
        mpz_cmp(p1->z, p2->z) == 0) {
        return 0;
    }
    return 1;
}

void point_print(const char* label, const point_t* p) {
    if (p == NULL) {
        printf("%s = NULL\n", label ? label : "Punto");
        return;
    }
    if (point_is_infinity(p)) {
        printf("%s = (0, 1, 0) [Punto al infinito (O)]\n", label ? label : "Punto");
    } else {
        gmp_printf("%s = (%Zd, %Zd, %Zd)\n", label ? label : "Punto", p->x, p->y, p->z);
    }
}

void elipar_free_points(point_t* points, size_t count) {
    if (points != NULL) {
        for (size_t i = 0; i < count; i++) {
            point_clear(&points[i]);
        }
        free(points);
    }
}

/* =========================================================================
 * 2. PARSER DE EXPRESIONES NUMERICAS Y POTENCIAS
 * Permite ingresar: 65537, 2^31 - 1, 2^61 - 1, 2^255 - 19, (2^16) + 1, etc.
 * ========================================================================= */

static void skip_spaces(const char** p) {
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

static int parse_expr_internal(mpz_t rop, const char** p);

static int parse_factor_internal(mpz_t rop, const char** p) {
    skip_spaces(p);
    if (**p == '\0') return -1;

    /* Signo mas unario */
    if (**p == '+') {
        (*p)++;
        return parse_factor_internal(rop, p);
    }

    /* Signo menos unario */
    if (**p == '-') {
        (*p)++;
        if (parse_factor_internal(rop, p) != 0) return -1;
        mpz_neg(rop, rop);
        return 0;
    }

    /* Parentesis */
    if (**p == '(') {
        (*p)++;
        if (parse_expr_internal(rop, p) != 0) return -1;
        skip_spaces(p);
        if (**p != ')') return -1;
        (*p)++;
        return 0;
    }

    /* Hexadecimal con prefijo 0x o 0X */
    if ((*p)[0] == '0' && ((*p)[1] == 'x' || (*p)[1] == 'X')) {
        *p += 2;
        const char* start = *p;
        while (isxdigit((unsigned char)**p)) (*p)++;
        size_t len = (size_t)(*p - start);
        if (len == 0) return -1;
        char* buf = (char*)malloc(len + 1);
        memcpy(buf, start, len);
        buf[len] = '\0';
        int ok = mpz_set_str(rop, buf, 16);
        free(buf);
        return (ok == 0) ? 0 : -1;
    }

    /* Numero decimal */
    if (isdigit((unsigned char)**p)) {
        const char* start = *p;
        while (isdigit((unsigned char)**p)) (*p)++;
        size_t len = (size_t)(*p - start);
        char* buf = (char*)malloc(len + 1);
        memcpy(buf, start, len);
        buf[len] = '\0';
        int ok = mpz_set_str(rop, buf, 10);
        free(buf);
        return (ok == 0) ? 0 : -1;
    }

    return -1;
}

static int parse_power_internal(mpz_t rop, const char** p) {
    if (parse_factor_internal(rop, p) != 0) return -1;
    skip_spaces(p);
    if (**p == '^') {
        (*p)++;
        mpz_t exp;
        mpz_init(exp);
        if (parse_power_internal(exp, p) != 0) {
            mpz_clear(exp);
            return -1;
        }
        if (!mpz_fits_ulong_p(exp)) {
            mpz_clear(exp);
            return -1;
        }
        unsigned long e = mpz_get_ui(exp);
        mpz_pow_ui(rop, rop, e);
        mpz_clear(exp);
    }
    return 0;
}

static int parse_term_internal(mpz_t rop, const char** p) {
    if (parse_power_internal(rop, p) != 0) return -1;
    skip_spaces(p);
    while (**p == '*') {
        (*p)++;
        mpz_t rhs;
        mpz_init(rhs);
        if (parse_power_internal(rhs, p) != 0) {
            mpz_clear(rhs);
            return -1;
        }
        mpz_mul(rop, rop, rhs);
        mpz_clear(rhs);
        skip_spaces(p);
    }
    return 0;
}

static int parse_expr_internal(mpz_t rop, const char** p) {
    if (parse_term_internal(rop, p) != 0) return -1;
    skip_spaces(p);
    while (**p == '+' || **p == '-') {
        char op = **p;
        (*p)++;
        mpz_t rhs;
        mpz_init(rhs);
        if (parse_term_internal(rhs, p) != 0) {
            mpz_clear(rhs);
            return -1;
        }
        if (op == '+') {
            mpz_add(rop, rop, rhs);
        } else {
            mpz_sub(rop, rop, rhs);
        }
        mpz_clear(rhs);
        skip_spaces(p);
    }
    return 0;
}

int parse_mpz_expression(mpz_t rop, const char* str) {
    if (str == NULL) return -1;
    const char* p = str;
    skip_spaces(&p);
    if (*p == '\0') return -1;
    if (parse_expr_internal(rop, &p) != 0) return -1;
    skip_spaces(&p);
    if (*p != '\0') return -1; /* Caracteres sobrantes no validos */
    return 0;
}

int read_mpz_from_input(mpz_t rop, const char* prompt_msg) {
    size_t capacity = 1024;
    char* buffer = (char*)malloc(capacity);
    if (!buffer) return -1;
    
    while (1) {
        if (prompt_msg) {
            printf("%s", prompt_msg);
            fflush(stdout);
        }
        
        size_t pos = 0;
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            if (pos + 1 >= capacity) {
                capacity *= 2;
                char* new_buf = (char*)realloc(buffer, capacity);
                if (!new_buf) {
                    free(buffer);
                    return -1;
                }
                buffer = new_buf;
            }
            buffer[pos++] = (char)c;
        }
        if (c == EOF && pos == 0) {
            free(buffer);
            return -1;
        }
        buffer[pos] = '\0';
        
        while (pos > 0 && (buffer[pos - 1] == '\r')) {
            buffer[--pos] = '\0';
        }
        
        const char* p_str = buffer;
        skip_spaces(&p_str);
        if (*p_str == '\0') {
            continue;
        }
        if (parse_mpz_expression(rop, buffer) == 0) {
            free(buffer);
            return 0;
        }
        printf("  [!] Expresion invalida (intente de nuevo, ej. 2^31 - 1, 0x1A2B, 1234).\n");
    }
}

/* =========================================================================
 * 3. VERIFICACIONES MATEMATICAS Y DE NO-SINGULARIDAD
 * ========================================================================= */

bool elipar_is_singular(const mpz_t a, const mpz_t b, const mpz_t p) {
    mpz_t disc, a3, b2, mod_a, mod_b;
    mpz_inits(disc, a3, b2, mod_a, mod_b, NULL);

    mpz_mod(mod_a, a, p);
    mpz_mod(mod_b, b, p);

    /* 4a^3 mod p */
    mpz_powm_ui(a3, mod_a, 3, p);
    mpz_mul_ui(a3, a3, 4);

    /* 27b^2 mod p */
    mpz_powm_ui(b2, mod_b, 2, p);
    mpz_mul_ui(b2, b2, 27);

    /* Delta = 4a^3 + 27b^2 mod p */
    mpz_add(disc, a3, b2);
    mpz_mod(disc, disc, p);

    bool singular = (mpz_cmp_ui(disc, 0) == 0);
    mpz_clears(disc, a3, b2, mod_a, mod_b, NULL);
    return singular;
}

bool elipar_is_point_on_curve(const point_t* pt, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (pt == NULL) return false;
    if (point_is_infinity(pt)) return true;

    mpz_t lhs, rhs, x3, axz2, bz3, z2, z3, mod_a, mod_b;
    mpz_inits(lhs, rhs, x3, axz2, bz3, z2, z3, mod_a, mod_b, NULL);

    mpz_mod(mod_a, a, p);
    mpz_mod(mod_b, b, p);

    /* z2 = Z^2 mod p, z3 = Z^3 mod p */
    mpz_powm_ui(z2, pt->z, 2, p);
    mpz_powm_ui(z3, pt->z, 3, p);

    /* lhs = Y^2 * Z mod p */
    mpz_powm_ui(lhs, pt->y, 2, p);
    mpz_mul(lhs, lhs, pt->z);
    mpz_mod(lhs, lhs, p);

    /* rhs = X^3 + a*X*Z^2 + b*Z^3 mod p */
    mpz_powm_ui(x3, pt->x, 3, p);
    
    mpz_mul(axz2, mod_a, pt->x);
    mpz_mul(axz2, axz2, z2);
    mpz_mod(axz2, axz2, p);

    mpz_mul(bz3, mod_b, z3);
    mpz_mod(bz3, bz3, p);

    mpz_add(rhs, x3, axz2);
    mpz_add(rhs, rhs, bz3);
    mpz_mod(rhs, rhs, p);

    bool ok = (mpz_cmp(lhs, rhs) == 0);
    mpz_clears(lhs, rhs, x3, axz2, bz3, z2, z3, mod_a, mod_b, NULL);
    return ok;
}

/* =========================================================================
 * 4. SECCION 1: FUNCIONES PRELIMINARES
 * ========================================================================= */

qr_table_t* elipar_quadratic_residue(const mpz_t p) {
    if (mpz_cmp_ui(p, 3) <= 0) {
        fprintf(stderr, "Error(quad): Numero invalido, debe ser mayor a 3.\n");
        return NULL;
    }

    /* La tabla hash exhaustiva en memoria esta acotada a primos moderados (p <= 200,000) */
    if (mpz_cmp_ui(p, 200000) > 0) {
        gmp_fprintf(stderr, "Aviso(quad): p = %Zd es demasiado grande para listar exhaustivamente todos sus residuos cuadraticos en RAM.\n", p);
        return NULL;
    }

    unsigned long p_val = mpz_get_ui(p);

    qr_table_t* table = (qr_table_t*)malloc(sizeof(qr_table_t));
    if (table == NULL) {
        perror("Error(quad): Error al asignar memoria a la tabla hash");
        return NULL;
    }

    table->capacity = (size_t)p_val;
    table->count = 0;
    table->p = p_val;
    table->entries = (qr_entry_t*)calloc(table->capacity, sizeof(qr_entry_t));
    if (table->entries == NULL) {
        perror("Error(quad): Error al asignar memoria a las entradas de la tabla");
        free(table);
        return NULL;
    }

    printf("=== Residuos cuadraticos y sus raices modulo %lu ===\n", p_val);

    size_t limit = (size_t)((p_val - 1) / 2);
    for (size_t y = 0; y <= limit; y++) {
        unsigned long r = (unsigned long)(((unsigned long long)y * y) % p_val);

        qr_entry_t* entry = &table->entries[r];
        entry->key = r;
        entry->is_occupied = true;

        if (y == 0) {
            entry->roots[0] = 0;
            entry->roots[1] = 0;
            entry->root_count = 1;
            printf("Residuo cuadratico: %-6lu | Raices: { %lu }\n", r, entry->roots[0]);
        } else {
            entry->roots[0] = (unsigned long)y;
            entry->roots[1] = p_val - (unsigned long)y;
            entry->root_count = 2;
            printf("Residuo cuadratico: %-6lu | Raices: { %lu, %lu }\n", r, entry->roots[0], entry->roots[1]);
        }
        table->count++;
    }

    printf("Total de residuos cuadraticos encontrados: %zu\n\n", table->count);
    return table;
}

const qr_entry_t* elipar_qr_lookup(const qr_table_t* table, const unsigned long residue) {
    if (table == NULL || table->entries == NULL || table->p == 0) {
        return NULL;
    }
    unsigned long norm = residue % table->p;
    if (table->entries[norm].is_occupied) {
        return &table->entries[norm];
    }
    return NULL;
}

void elipar_qr_free(qr_table_t* table) {
    if (table != NULL) {
        if (table->entries != NULL) {
            free(table->entries);
            table->entries = NULL;
        }
        free(table);
    }
}

point_t* elipar_rational_points(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points) {
    if (num_points != NULL) {
        *num_points = 0;
    }

    if (mpz_cmp_ui(p, 3) <= 0) {
        fprintf(stderr, "Error(rati): Numero invalido, p debe ser mayor a 3.\n");
        return NULL;
    }

    if (elipar_is_singular(a, b, p)) {
        gmp_fprintf(stderr, "Error(rati): Curva eliptica singular (4a^3 + 27b^2 = 0 mod %Zd).\n", p);
        return NULL;
    }

    if (mpz_cmp_ui(p, 200000) > 0) {
        gmp_fprintf(stderr, "Aviso(rati): p = %Zd es muy grande para buscar y almacenar todos los puntos exhaustivamente (O(p)). Use la seccion de aritmetica para criptografia con enteros grandes.\n", p);
        return NULL;
    }

    unsigned long p_val = mpz_get_ui(p);

    /* Generar tabla de residuos cuadraticos */
    qr_table_t* qr_table = elipar_quadratic_residue(p);
    if (qr_table == NULL) {
        return NULL;
    }

    /* Como maximo 2p + 1 puntos (incluyendo punto al infinito) */
    size_t max_capacity = 2 * (size_t)p_val + 1;
    point_t* points = (point_t*)malloc(sizeof(point_t) * max_capacity);
    if (points == NULL) {
        perror("Error(rati): Error al asignar memoria para puntos");
        elipar_qr_free(qr_table);
        return NULL;
    }

    for (size_t i = 0; i < max_capacity; i++) {
        point_init(&points[i]);
    }

    size_t count = 0;

    /* 1. Punto al infinito: (0, 1, 0) */
    point_set_infinity(&points[count]);
    count++;

    /* 2. Puntos afines (x, y, 1) */
    mpz_t mod_a, mod_b, x3, ax, rhs;
    mpz_inits(mod_a, mod_b, x3, ax, rhs, NULL);
    mpz_mod(mod_a, a, p);
    mpz_mod(mod_b, b, p);

    for (unsigned long x = 0; x < p_val; x++) {
        mpz_t x_mpz;
        mpz_init_set_ui(x_mpz, x);

        mpz_powm_ui(x3, x_mpz, 3, p);
        mpz_mul(ax, mod_a, x_mpz);
        mpz_mod(ax, ax, p);

        mpz_add(rhs, x3, ax);
        mpz_add(rhs, rhs, mod_b);
        mpz_mod(rhs, rhs, p);

        unsigned long rhs_val = mpz_get_ui(rhs);
        const qr_entry_t* entry = elipar_qr_lookup(qr_table, rhs_val);

        if (entry != NULL) {
            for (int k = 0; k < entry->root_count; k++) {
                point_set_ui(&points[count], x, entry->roots[k], 1);
                count++;
            }
        }

        mpz_clear(x_mpz);
    }

    mpz_clears(mod_a, mod_b, x3, ax, rhs, NULL);
    elipar_qr_free(qr_table);

    /* Liberar memoria de posiciones no usadas */
    for (size_t i = count; i < max_capacity; i++) {
        point_clear(&points[i]);
    }

    point_t* resized = (point_t*)realloc(points, sizeof(point_t) * count);
    if (resized != NULL) {
        points = resized;
    }

    if (num_points != NULL) {
        *num_points = count;
    }

    printf("Total de puntos racionales encontrados (incluyendo punto al infinito): %zu\n\n", count);
    return points;
}

point_t* elipar_rational(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points) {
    return elipar_rational_points(a, b, p, num_points);
}

size_t elipar_count_rational_points(const mpz_t a, const mpz_t b, const mpz_t p) {
    size_t count = 0;
    point_t* pts = elipar_rational_points(a, b, p, &count);
    if (pts != NULL) {
        elipar_free_points(pts, count);
    }
    return count;
}

int elipar_points_to_csv(const char* filename, const point_t* points, const size_t num_points, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (filename == NULL || points == NULL) {
        fprintf(stderr, "Error(csv): Parametros invalidos para exportar a CSV.\n");
        return 1;
    }

    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error(csv): No se pudo abrir el archivo CSV para escritura");
        return 1;
    }

    /* Formato estandar del laboratorio:
     * ,p,<valor>
     * ,a,<valor>
     * ,b,<valor>
     * ,count,<conteo>
     * x,y,z
     */
    gmp_fprintf(file, ",p,%Zd\n", p);
    gmp_fprintf(file, ",a,%Zd\n", a);
    gmp_fprintf(file, ",b,%Zd\n", b);
    fprintf(file, ",count,%zu\n", num_points);
    fprintf(file, "x,y,z\n");

    for (size_t i = 0; i < num_points; i++) {
        gmp_fprintf(file, "%Zd,%Zd,%Zd\n", points[i].x, points[i].y, points[i].z);
    }

    fclose(file);
    printf("Puntos racionales exportados exitosamente a '%s' (%zu puntos en total).\n", filename, num_points);
    return 0;
}

int elipar_is_in(const int a, const size_t len, const int* arr) {
    if (arr == NULL) return -1;
    for (size_t i = 0; i < len; i++) {
        if (arr[i] == a) return (int)i;
    }
    return -1;
}

/* =========================================================================
 * 5. SECCION 2: ARITMETICA DE CURVAS ELIPTICAS CON GMP
 * ========================================================================= */

int elipar_generate_curve(mpz_t p, mpz_t a, mpz_t b, unsigned int n_bits, gmp_randstate_t state) {
    if (n_bits < 3) {
        fprintf(stderr, "Error: La longitud en bits debe ser al menos 3 (primos > 3).\n");
        return -1;
    }

    /* 1. Generar primo aleatorio p de exactamente n_bits */
    do {
        mpz_urandomb(p, state, n_bits);
        mpz_setbit(p, n_bits - 1); /* Asegura que tenga exactamente n bits */
        mpz_setbit(p, 0);          /* Asegura que sea impar */
        mpz_nextprime(p, p);
    } while (mpz_sizeinbase(p, 2) != n_bits || mpz_cmp_ui(p, 3) <= 0);

    /* 2. Encontrar valores aleatorios a, b en [0, p-1] para curva no-singular */
    do {
        mpz_urandomm(a, state, p);
        mpz_urandomm(b, state, p);
    } while (elipar_is_singular(a, b, p));

    return 0;
}

int elipar_point_add(point_t* R, const point_t* P, const point_t* Q, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL || Q == NULL) return -1;

    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }
    if (!elipar_is_point_on_curve(Q, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto Q no pertenece a la curva.\n");
        return -1;
    }

    if (point_is_infinity(P)) {
        point_set(R, Q);
        return 0;
    }
    if (point_is_infinity(Q)) {
        point_set(R, P);
        return 0;
    }

    mpz_t u1, u2, v1, v2, u, v, w, a_val, x3, y3, z3;
    mpz_t v2_sq, v3, tmp1, tmp2;
    mpz_inits(u1, u2, v1, v2, u, v, w, a_val, x3, y3, z3, v2_sq, v3, tmp1, tmp2, NULL);

    /* u1 = Y2 * Z1 */
    mpz_mul(u1, Q->y, P->z);
    mpz_mod(u1, u1, p);

    /* u2 = Y1 * Z2 */
    mpz_mul(u2, P->y, Q->z);
    mpz_mod(u2, u2, p);

    /* v1 = X2 * Z1 */
    mpz_mul(v1, Q->x, P->z);
    mpz_mod(v1, v1, p);

    /* v2 = X1 * Z2 */
    mpz_mul(v2, P->x, Q->z);
    mpz_mod(v2, v2, p);

    /* v = v1 - v2 */
    mpz_sub(v, v1, v2);
    mpz_mod(v, v, p);

    /* u = u1 - u2 */
    mpz_sub(u, u1, u2);
    mpz_mod(u, u, p);

    if (mpz_cmp_ui(v, 0) == 0) {
        if (mpz_cmp_ui(u, 0) == 0) {
            /* P == Q => Double */
            mpz_clears(u1, u2, v1, v2, u, v, w, a_val, x3, y3, z3, v2_sq, v3, tmp1, tmp2, NULL);
            return elipar_point_double(R, P, a, b, p);
        } else {
            /* P == -Q => Infinity */
            point_set_infinity(R);
            mpz_clears(u1, u2, v1, v2, u, v, w, a_val, x3, y3, z3, v2_sq, v3, tmp1, tmp2, NULL);
            return 0;
        }
    }

    /* w = Z1 * Z2 */
    mpz_mul(w, P->z, Q->z);
    mpz_mod(w, w, p);

    /* v2_sq = v^2 */
    mpz_powm_ui(v2_sq, v, 2, p);

    /* v3 = v^3 */
    mpz_powm_ui(v3, v, 3, p);

    /* a_val = u^2 * w - v^3 - 2 * v^2 * v2 */
    mpz_powm_ui(a_val, u, 2, p);
    mpz_mul(a_val, a_val, w);
    mpz_sub(a_val, a_val, v3);
    
    mpz_mul(tmp1, v2_sq, v2);
    mpz_mul_ui(tmp1, tmp1, 2);
    mpz_sub(a_val, a_val, tmp1);
    mpz_mod(a_val, a_val, p);

    /* x3 = v * a_val */
    mpz_mul(x3, v, a_val);
    mpz_mod(x3, x3, p);

    /* y3 = u * (v^2 * v2 - a_val) - v^3 * u2 */
    mpz_mul(tmp1, v2_sq, v2);
    mpz_sub(tmp1, tmp1, a_val);
    mpz_mul(y3, u, tmp1);

    mpz_mul(tmp2, v3, u2);
    mpz_sub(y3, y3, tmp2);
    mpz_mod(y3, y3, p);

    /* z3 = v^3 * w */
    mpz_mul(z3, v3, w);
    mpz_mod(z3, z3, p);

    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set(R->z, z3);

    mpz_clears(u1, u2, v1, v2, u, v, w, a_val, x3, y3, z3, v2_sq, v3, tmp1, tmp2, NULL);
    return 0;
}

int elipar_point_double(point_t* R, const point_t* P, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL) return -1;

    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }

    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return 0;
    }
    
    if (mpz_cmp_ui(P->y, 0) == 0) {
        point_set_infinity(R);
        return 0;
    }

    mpz_t w, s, b_val, h, x3, y3, z3, tmp1, tmp2;
    mpz_inits(w, s, b_val, h, x3, y3, z3, tmp1, tmp2, NULL);

    /* w = a*Z^2 + 3*X^2 */
    mpz_powm_ui(tmp1, P->z, 2, p);
    mpz_mul(tmp1, tmp1, a);
    
    mpz_powm_ui(tmp2, P->x, 2, p);
    mpz_mul_ui(tmp2, tmp2, 3);
    
    mpz_add(w, tmp1, tmp2);
    mpz_mod(w, w, p);

    /* s = Y * Z */
    mpz_mul(s, P->y, P->z);
    mpz_mod(s, s, p);

    /* b_val = X * Y * S */
    mpz_mul(b_val, P->x, P->y);
    mpz_mul(b_val, b_val, s);
    mpz_mod(b_val, b_val, p);

    /* h = w^2 - 8*b_val */
    mpz_powm_ui(h, w, 2, p);
    mpz_mul_ui(tmp1, b_val, 8);
    mpz_sub(h, h, tmp1);
    mpz_mod(h, h, p);

    /* x3 = 2 * h * s */
    mpz_mul(x3, h, s);
    mpz_mul_ui(x3, x3, 2);
    mpz_mod(x3, x3, p);

    /* y3 = w*(4*b_val - h) - 8*Y^2*S^2 */
    mpz_mul_ui(tmp1, b_val, 4);
    mpz_sub(tmp1, tmp1, h);
    mpz_mul(tmp1, tmp1, w);

    mpz_powm_ui(tmp2, P->y, 2, p);
    mpz_t s2; mpz_init(s2);
    mpz_powm_ui(s2, s, 2, p);
    mpz_mul(tmp2, tmp2, s2);
    mpz_mul_ui(tmp2, tmp2, 8);
    
    mpz_sub(y3, tmp1, tmp2);
    mpz_mod(y3, y3, p);

    /* z3 = 8 * s^3 */
    mpz_powm_ui(z3, s, 3, p);
    mpz_mul_ui(z3, z3, 8);
    mpz_mod(z3, z3, p);

    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set(R->z, z3);

    mpz_clear(s2);
    mpz_clears(w, s, b_val, h, x3, y3, z3, tmp1, tmp2, NULL);
    return 0;
}

int elipar_projective_to_affine(point_t* R, const point_t* P, const mpz_t p) {
    if (R == NULL || P == NULL) return -1;
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return 0;
    }
    
    mpz_t inv_z;
    mpz_init(inv_z);
    
    if (mpz_invert(inv_z, P->z, p) == 0) {
        mpz_clear(inv_z);
        return -1;
    }
    
    mpz_mul(R->x, P->x, inv_z);
    mpz_mod(R->x, R->x, p);
    
    mpz_mul(R->y, P->y, inv_z);
    mpz_mod(R->y, R->y, p);
    
    mpz_set_ui(R->z, 1);
    
    mpz_clear(inv_z);
    return 0;
}

int elipar_point_mul_r2l(point_t* R, const point_t* P, const mpz_t k, const mpz_t a, const mpz_t b, const mpz_t p, bool print_steps) {
    if (R == NULL || P == NULL) return -1;
    
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }

    point_t res, temp;
    point_init(&res);
    point_init(&temp);
    
    point_set_infinity(&res);
    point_set(&temp, P);
    
    mpz_t k_copy;
    mpz_init_set(k_copy, k);
    
    if (mpz_cmp_ui(k_copy, 0) < 0) {
        mpz_neg(k_copy, k_copy);
        mpz_sub(temp.y, p, temp.y);
        mpz_mod(temp.y, temp.y, p);
    }
    
    size_t i = 0;
    while (mpz_cmp_ui(k_copy, 0) > 0) {
        if (mpz_odd_p(k_copy)) {
            elipar_point_add(&res, &res, &temp, a, b, p);
            if (print_steps) {
                printf("  [R2L i=%zu] k_i=1 -> Q = Q + P_i. Actual Q: ", i);
                point_t res_aff; point_init(&res_aff);
                elipar_projective_to_affine(&res_aff, &res, p);
                if (point_is_infinity(&res_aff)) printf("O\n");
                else gmp_printf("(%Zd, %Zd)\n", res_aff.x, res_aff.y);
                point_clear(&res_aff);
            }
        } else {
            if (print_steps) {
                printf("  [R2L i=%zu] k_i=0 -> Omitir suma.\n", i);
            }
        }
        elipar_point_double(&temp, &temp, a, b, p);
        mpz_fdiv_q_2exp(k_copy, k_copy, 1);
        i++;
    }
    
    point_set(R, &res);
    
    mpz_clear(k_copy);
    point_clear(&res);
    point_clear(&temp);
    return 0;
}

int elipar_point_mul_l2r(point_t* R, const point_t* P, const mpz_t k, const mpz_t a, const mpz_t b, const mpz_t p, bool print_steps) {
    if (R == NULL || P == NULL) return -1;
    
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }

    point_t res, temp_p;
    point_init(&res);
    point_init(&temp_p);
    
    point_set_infinity(&res);
    point_set(&temp_p, P);
    
    mpz_t k_copy;
    mpz_init_set(k_copy, k);
    
    if (mpz_cmp_ui(k_copy, 0) < 0) {
        mpz_neg(k_copy, k_copy);
        mpz_sub(temp_p.y, p, temp_p.y);
        mpz_mod(temp_p.y, temp_p.y, p);
    }
    
    if (mpz_cmp_ui(k_copy, 0) == 0) {
        point_set_infinity(R);
        mpz_clear(k_copy);
        point_clear(&res);
        point_clear(&temp_p);
        return 0;
    }

    size_t num_bits = mpz_sizeinbase(k_copy, 2);
    for (long i = num_bits - 1; i >= 0; i--) {
        elipar_point_double(&res, &res, a, b, p);
        if (print_steps) {
             printf("  [L2R i=%ld] Q = 2Q. Actual Q: ", i);
             point_t res_aff; point_init(&res_aff);
             elipar_projective_to_affine(&res_aff, &res, p);
             if (point_is_infinity(&res_aff)) printf("O\n");
             else gmp_printf("(%Zd, %Zd)\n", res_aff.x, res_aff.y);
             point_clear(&res_aff);
        }

        if (mpz_tstbit(k_copy, i)) {
            elipar_point_add(&res, &res, &temp_p, a, b, p);
            if (print_steps) {
                printf("  [L2R i=%ld] k_i=1 -> Q = Q + P. Actual Q: ", i);
                point_t res_aff; point_init(&res_aff);
                elipar_projective_to_affine(&res_aff, &res, p);
                if (point_is_infinity(&res_aff)) printf("O\n");
                else gmp_printf("(%Zd, %Zd)\n", res_aff.x, res_aff.y);
                point_clear(&res_aff);
            }
        } else {
            if (print_steps) {
                printf("  [L2R i=%ld] k_i=0 -> Omitir suma.\n", i);
            }
        }
    }
    
    point_set(R, &res);
    
    mpz_clear(k_copy);
    point_clear(&res);
    point_clear(&temp_p);
    return 0;
}


/* =========================================================================
 * 6. SECCION 3: CASOS DE PRUEBA Y PREGUNTAS DEL LABORATORIO
 * ========================================================================= */

void elipar_run_section3_question2(void) {
    printf("\n======================================================================\n");
    printf(" PREGUNTA 2 (SECCION 3): GENERACION DE PRIMOS Y CURVAS NO SINGULARES\n");
    printf(" Tamaños requeridos: 16, 32, 64, 512, 1024 y 2048 bits\n");
    printf("======================================================================\n");

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) ^ 0x5DEECE66DL);

    unsigned int bit_sizes[] = {16, 32, 64, 512, 1024, 2048};
    size_t num_tests = sizeof(bit_sizes) / sizeof(bit_sizes[0]);

    for (size_t i = 0; i < num_tests; i++) {
        unsigned int bits = bit_sizes[i];
        mpz_t p, a, b;
        mpz_inits(p, a, b, NULL);

        clock_t start = clock();
        elipar_generate_curve(p, a, b, bits, state);
        clock_t end = clock();
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

        printf("\n--- Curva no singular generada de %u bits (tiempo: %.4f s) ---\n", bits, elapsed);
        gmp_printf("Primo p (%u bits):\n  %Zd\n", (unsigned int)mpz_sizeinbase(p, 2), p);
        gmp_printf("Parametro a:\n  %Zd\n", a);
        gmp_printf("Parametro b:\n  %Zd\n", b);
        printf("Ecuacion de la curva:\n  y^2 = x^3 + ax + b (mod p)\n");
        printf("No singularidad verificada: %s\n", (!elipar_is_singular(a, b, p)) ? "SI (Delta != 0 mod p)" : "NO");

        mpz_clears(p, a, b, NULL);
    }

    gmp_randclear(state);
    printf("\n======================================================================\n\n");
}

static void run_one_question3_case(const char* label, const char* p_expr,
                                  const char* a_expr, const char* b_expr,
                                  const char* px_expr, const char* py_expr,
                                  const char* qx_expr, const char* qy_expr) {
    printf("\n----------------------------------------------------------------------\n");
    printf(" CASO %s:\n", label);
    printf(" Modulo p: %s\n", p_expr);
    printf(" Curva: y^2 = x^3 + (%s)x + (%s) (mod p)\n", a_expr, b_expr);
    printf("----------------------------------------------------------------------\n");

    mpz_t p, a, b;
    mpz_inits(p, a, b, NULL);
    parse_mpz_expression(p, p_expr);
    parse_mpz_expression(a, a_expr);
    parse_mpz_expression(b, b_expr);

    point_t P, Q, P_plus_Q, two_P, two_Q;
    point_init(&P); point_init(&Q);
    point_init(&P_plus_Q); point_init(&two_P); point_init(&two_Q);

    parse_mpz_expression(P.x, px_expr);
    parse_mpz_expression(P.y, py_expr);
    mpz_set_ui(P.z, 1);

    parse_mpz_expression(Q.x, qx_expr);
    parse_mpz_expression(Q.y, qy_expr);
    mpz_set_ui(Q.z, 1);

    gmp_printf("Primo p = %Zd (%u bits)\n", p, (unsigned int)mpz_sizeinbase(p, 2));
    gmp_printf("a = %Zd,  b = %Zd\n", a, b);
    point_print("P", &P);
    point_print("Q", &Q);

    bool p_on = elipar_is_point_on_curve(&P, a, b, p);
    bool q_on = elipar_is_point_on_curve(&Q, a, b, p);
    printf("Verificacion: P pertenece a E: %s | Q pertenece a E: %s\n\n",
           p_on ? "SI [VALIDO]" : "NO [ERROR]",
           q_on ? "SI [VALIDO]" : "NO [ERROR]");

    if (elipar_point_add(&P_plus_Q, &P, &Q, a, b, p) == 0) {
        point_print("Resultado P + Q", &P_plus_Q);
        printf("P + Q pertenece a la curva: %s\n",
               elipar_is_point_on_curve(&P_plus_Q, a, b, p) ? "SI [CORRECTO]" : "NO");
    }

    if (elipar_point_double(&two_P, &P, a, b, p) == 0) {
        point_print("Resultado 2P", &two_P);
        printf("2P pertenece a la curva: %s\n",
               elipar_is_point_on_curve(&two_P, a, b, p) ? "SI [CORRECTO]" : "NO");
    }

    if (elipar_point_double(&two_Q, &Q, a, b, p) == 0) {
        point_print("Resultado 2Q", &two_Q);
        printf("2Q pertenece a la curva: %s\n",
               elipar_is_point_on_curve(&two_Q, a, b, p) ? "SI [CORRECTO]" : "NO");
    }

    point_clear(&P); point_clear(&Q);
    point_clear(&P_plus_Q); point_clear(&two_P); point_clear(&two_Q);
    mpz_clears(p, a, b, NULL);
}

void elipar_run_section3_question3(void) {
    printf("\n======================================================================\n");
    printf(" PREGUNTA 3 (SECCION 3): COMPUTO DE P + Q, 2P y 2Q\n");
    printf(" Evaluacion automatica de los incisos a), b), c) y d)\n");
    printf("======================================================================\n");

    /* a) E: y^2 = x^3 + x + 1 mod 65537, P = (49606, 64426, 1), Q = (2565, 62370, 1) */
    run_one_question3_case(
        "a",
        "65537",
        "1", "1",
        "49606", "64426",
        "2565", "62370"
    );

    /* b) E: y^2 = x^3 + 30x + 97 mod 4294967311, P = (433318550, 1866632789, 1), Q = (408186704, 4022951807, 1) */
    run_one_question3_case(
        "b",
        "4294967311",
        "30", "97",
        "433318550", "1866632789",
        "408186704", "4022951807"
    );

    /* c) E: y^2 = x^3 + 125x + 2 mod 2^31 - 1, P = (1506532484, 1041296099, 1), Q = (1624813594, 253477454, 1) */
    run_one_question3_case(
        "c",
        "2^31 - 1",
        "125", "2",
        "1506532484", "1041296099",
        "1624813594", "253477454"
    );

    /* d) E: y^2 = x^3 + x + 1300 mod 2^61 - 1, P = (1317571598731990128, 494998261481053431, 1), Q = (590181223958911612, 1863749232038030155, 1) */
    run_one_question3_case(
        "d",
        "2^61 - 1",
        "1", "1300",
        "1317571598731990128", "494998261481053431",
        "590181223958911612", "1863749232038030155"
    );

    printf("\n======================================================================\n\n");
}

int elipar_ecdsa_verify(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, const point_t* G, const point_t* Q, const mpz_t e, const mpz_t r, const mpz_t s) {
    if (mpz_cmp_ui(r, 1) < 0 || mpz_cmp(r, n) >= 0) return 0;
    if (mpz_cmp_ui(s, 1) < 0 || mpz_cmp(s, n) >= 0) return 0;
    mpz_t w, u1, u2; mpz_inits(w, u1, u2, NULL);
    if (mpz_invert(w, s, n) == 0) { mpz_clears(w, u1, u2, NULL); return 0; }
    mpz_mul(u1, e, w); mpz_mod(u1, u1, n);
    mpz_mul(u2, r, w); mpz_mod(u2, u2, n);
    point_t u1G, u2Q, R_proj, R_aff;
    point_init(&u1G); point_init(&u2Q); point_init(&R_proj); point_init(&R_aff);
    elipar_point_mul_l2r(&u1G, G, u1, a, b, p, false);
    elipar_point_mul_l2r(&u2Q, Q, u2, a, b, p, false);
    elipar_point_add(&R_proj, &u1G, &u2Q, a, b, p);
    if (point_is_infinity(&R_proj)) {
        point_clear(&u1G); point_clear(&u2Q); point_clear(&R_proj); point_clear(&R_aff); mpz_clears(w, u1, u2, NULL); return 0;
    }
    elipar_projective_to_affine(&R_aff, &R_proj, p);
    mpz_t rx_mod_n; mpz_init(rx_mod_n); mpz_mod(rx_mod_n, R_aff.x, n);
    int valid = (mpz_cmp(rx_mod_n, r) == 0);
    mpz_clear(rx_mod_n); point_clear(&u1G); point_clear(&u2Q); point_clear(&R_proj); point_clear(&R_aff); mpz_clears(w, u1, u2, NULL);
    return valid;
}


int elipar_ecdsa_sign(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, const point_t* G, const mpz_t d, const mpz_t e, const mpz_t k_nonce, mpz_t r, mpz_t s) {
    if (mpz_cmp_ui(k_nonce, 1) < 0 || mpz_cmp(k_nonce, n) >= 0) return -1;
    point_t R_proj, R_aff;
    point_init(&R_proj); point_init(&R_aff);
    elipar_point_mul_l2r(&R_proj, G, k_nonce, a, b, p, false);
    elipar_projective_to_affine(&R_aff, &R_proj, p);
    mpz_mod(r, R_aff.x, n);
    if (mpz_cmp_ui(r, 0) == 0) { point_clear(&R_proj); point_clear(&R_aff); return -1; }
    mpz_t k_inv, dr, e_plus_dr;
    mpz_inits(k_inv, dr, e_plus_dr, NULL);
    if (mpz_invert(k_inv, k_nonce, n) == 0) { point_clear(&R_proj); point_clear(&R_aff); mpz_clears(k_inv, dr, e_plus_dr, NULL); return -1; }
    mpz_mul(dr, d, r);
    mpz_add(e_plus_dr, e, dr);
    mpz_mul(s, k_inv, e_plus_dr);
    mpz_mod(s, s, n);
    if (mpz_cmp_ui(s, 0) == 0) { point_clear(&R_proj); point_clear(&R_aff); mpz_clears(k_inv, dr, e_plus_dr, NULL); return -1; }
    point_clear(&R_proj); point_clear(&R_aff);
    mpz_clears(k_inv, dr, e_plus_dr, NULL);
    return 0;
}
