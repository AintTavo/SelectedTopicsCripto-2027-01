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
    char buffer[1024];
    while (1) {
        if (prompt_msg) {
            printf("%s", prompt_msg);
            fflush(stdout);
        }
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            return -1;
        }
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {
            buffer[--len] = '\0';
        }
        const char* p = buffer;
        skip_spaces(&p);
        if (*p == '\0') {
            continue;
        }
        if (parse_mpz_expression(rop, buffer) == 0) {
            return 0;
        }
        printf("  [!] Expresion invalida: '%s'. Intente de nuevo (ej. 65537, 2^31 - 1, 2^61 - 1).\n", buffer);
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

    mpz_t lhs, rhs, x3, ax, mod_a, mod_b;
    mpz_inits(lhs, rhs, x3, ax, mod_a, mod_b, NULL);

    mpz_mod(mod_a, a, p);
    mpz_mod(mod_b, b, p);

    /* lhs = y^2 mod p */
    mpz_powm_ui(lhs, pt->y, 2, p);

    /* rhs = (x^3 + ax + b) mod p */
    mpz_powm_ui(x3, pt->x, 3, p);
    mpz_mul(ax, mod_a, pt->x);
    mpz_mod(ax, ax, p);

    mpz_add(rhs, x3, ax);
    mpz_add(rhs, rhs, mod_b);
    mpz_mod(rhs, rhs, p);

    bool ok = (mpz_cmp(lhs, rhs) == 0);
    mpz_clears(lhs, rhs, x3, ax, mod_a, mod_b, NULL);
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

    /* Validacion de pertenencia a la curva */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P = (%Zd, %Zd, %Zd) no pertenece a la curva.\n", P->x, P->y, P->z);
        return -1;
    }
    if (!elipar_is_point_on_curve(Q, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto Q = (%Zd, %Zd, %Zd) no pertenece a la curva.\n", Q->x, Q->y, Q->z);
        return -1;
    }

    /* Caso P = O (infinito) => P + Q = Q */
    if (point_is_infinity(P)) {
        point_set(R, Q);
        return 0;
    }

    /* Caso Q = O (infinito) => P + Q = P */
    if (point_is_infinity(Q)) {
        point_set(R, P);
        return 0;
    }

    /* Normalizacion de coordenadas modulo p */
    mpz_t px, py, qx, qy;
    mpz_inits(px, py, qx, qy, NULL);
    mpz_mod(px, P->x, p);
    mpz_mod(py, P->y, p);
    mpz_mod(qx, Q->x, p);
    mpz_mod(qy, Q->y, p);

    /* Caso px == qx */
    if (mpz_cmp(px, qx) == 0) {
        mpz_t neg_qy;
        mpz_init(neg_qy);
        mpz_sub(neg_qy, p, qy);
        mpz_mod(neg_qy, neg_qy, p);

        /* Si py == -qy mod p => P = -Q => P + Q = O */
        if (mpz_cmp(py, neg_qy) == 0) {
            point_set_infinity(R);
            mpz_clear(neg_qy);
            mpz_clears(px, py, qx, qy, NULL);
            return 0;
        }
        mpz_clear(neg_qy);

        /* Si py == qy mod p => P == Q => Duplicacion de punto */
        if (mpz_cmp(py, qy) == 0) {
            mpz_clears(px, py, qx, qy, NULL);
            return elipar_point_double(R, P, a, b, p);
        }
    }

    /* Formula general para P != +-Q:
     * lambda = (y2 - y1) / (x2 - x1) mod p
     * x3 = lambda^2 - x1 - x2 mod p
     * y3 = lambda*(x1 - x3) - y1 mod p
     */
    mpz_t dy, dx, inv_dx, lambda, x3, y3, tmp;
    mpz_inits(dy, dx, inv_dx, lambda, x3, y3, tmp, NULL);

    mpz_sub(dy, qy, py);
    mpz_mod(dy, dy, p);

    mpz_sub(dx, qx, px);
    mpz_mod(dx, dx, p);

    if (mpz_invert(inv_dx, dx, p) == 0) {
        fprintf(stderr, "Error: No existe inverso modular de (x2 - x1) mod p.\n");
        mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
        return -1;
    }

    mpz_mul(lambda, dy, inv_dx);
    mpz_mod(lambda, lambda, p);

    /* x3 = lambda^2 - x1 - x2 mod p */
    mpz_powm_ui(x3, lambda, 2, p);
    mpz_sub(x3, x3, px);
    mpz_sub(x3, x3, qx);
    mpz_mod(x3, x3, p);

    /* y3 = lambda*(x1 - x3) - y1 mod p */
    mpz_sub(tmp, px, x3);
    mpz_mul(y3, lambda, tmp);
    mpz_sub(y3, y3, py);
    mpz_mod(y3, y3, p);

    /* Asignacion al punto destino R */
    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set_ui(R->z, 1);

    mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
    return 0;
}

int elipar_point_double(point_t* R, const point_t* P, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL) return -1;

    /* Validacion de pertenencia a la curva */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P = (%Zd, %Zd, %Zd) no pertenece a la curva.\n", P->x, P->y, P->z);
        return -1;
    }

    /* Caso P = O => 2P = O */
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return 0;
    }

    mpz_t px, py, mod_a;
    mpz_inits(px, py, mod_a, NULL);
    mpz_mod(px, P->x, p);
    mpz_mod(py, P->y, p);
    mpz_mod(mod_a, a, p);

    /* Si y == 0 mod p, la tangente es vertical => 2P = O */
    if (mpz_cmp_ui(py, 0) == 0) {
        point_set_infinity(R);
        mpz_clears(px, py, mod_a, NULL);
        return 0;
    }

    /* Formula de duplicacion:
     * lambda = (3*x1^2 + a) / (2*y1) mod p
     * x3 = lambda^2 - 2*x1 mod p
     * y3 = lambda*(x1 - x3) - y1 mod p
     */
    mpz_t num, den, inv_den, lambda, x3, y3, tmp;
    mpz_inits(num, den, inv_den, lambda, x3, y3, tmp, NULL);

    /* Numerador: 3*x1^2 + a mod p */
    mpz_powm_ui(num, px, 2, p);
    mpz_mul_ui(num, num, 3);
    mpz_add(num, num, mod_a);
    mpz_mod(num, num, p);

    /* Denominador: 2*y1 mod p */
    mpz_mul_ui(den, py, 2);
    mpz_mod(den, den, p);

    if (mpz_invert(inv_den, den, p) == 0) {
        fprintf(stderr, "Error: No existe inverso modular de 2*y1 mod p.\n");
        mpz_clears(num, den, inv_den, lambda, x3, y3, tmp, px, py, mod_a, NULL);
        return -1;
    }

    mpz_mul(lambda, num, inv_den);
    mpz_mod(lambda, lambda, p);

    /* x3 = lambda^2 - 2*x1 mod p */
    mpz_powm_ui(x3, lambda, 2, p);
    mpz_sub(x3, x3, px);
    mpz_sub(x3, x3, px);
    mpz_mod(x3, x3, p);

    /* y3 = lambda*(x1 - x3) - y1 mod p */
    mpz_sub(tmp, px, x3);
    mpz_mul(y3, lambda, tmp);
    mpz_sub(y3, y3, py);
    mpz_mod(y3, y3, p);

    /* Asignacion al punto destino R */
    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set_ui(R->z, 1);

    mpz_clears(num, den, inv_den, lambda, x3, y3, tmp, px, py, mod_a, NULL);
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