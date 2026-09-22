# Reporte Técnico - Laboratorio 01: Curvas Elípticas

**Instituto Politécnico Nacional**  
**Escuela Superior de Cómputo (ESCOM)**  
**Temas Selectos de Criptografía (Selected Topics in Cryptography)**  
**Sesión 1: Curvas Elípticas** — *Septiembre 2026*  

---

## 1. Información General

* **Institución:** Instituto Politécnico Nacional (IPN) - Escuela Superior de Cómputo (ESCOM)
* **Unidad de Aprendizaje:** Temas Selectos de Criptografía
* **Tema:** Residuos Cuadráticos, Puntos Racionales y Aritmética de Curvas Elípticas sobre Campos Finitos $\text{GF}(p)$ con Enteros Grandes (GMP)
* **Estudiante:** *[Nombre del Alumno]*
* **Boleta:** *[Número de Boleta]*
* **Fecha:** Septiembre 2026
* **Lenguaje utilizado:** C (con compilador GCC MinGW-w64 y biblioteca de precisión arbitraria GNU MP / GMP 6.3.0)

---

## 2. Sección 1: Funciones Preliminares (Código y Explicación)

### 2.1. Ejercicio 1.1: Residuos Cuadráticos y Raíces Módulo $p > 3$

#### Objetivo:
Diseñar e implementar una función que reciba un número primo $p > 3$, imprima todos los residuos cuadráticos módulo $p$ ($\text{QR}_p$) y para cada uno imprima sus raíces cuadradas.

#### Bloque de Código (`elipt_curve.c` y `elipt_curve.h`):

```c
/* Estructura para almacenar cada residuo y sus raices */
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

qr_table_t* elipar_quadratic_residue(const mpz_t p) {
    if (mpz_cmp_ui(p, 3) <= 0) {
        fprintf(stderr, "Error(quad): Numero invalido, debe ser mayor a 3.\n");
        return NULL;
    }

    if (mpz_cmp_ui(p, 200000) > 0) {
        gmp_fprintf(stderr, "Aviso(quad): p = %Zd es demasiado grande para listar en memoria.\n", p);
        return NULL;
    }

    unsigned long p_val = mpz_get_ui(p);

    qr_table_t* table = (qr_table_t*)malloc(sizeof(qr_table_t));
    if (table == NULL) return NULL;

    table->capacity = (size_t)p_val;
    table->count = 0;
    table->p = p_val;
    table->entries = (qr_entry_t*)calloc(table->capacity, sizeof(qr_entry_t));
    if (table->entries == NULL) {
        free(table);
        return NULL;
    }

    printf("=== Residuos cuadraticos y sus raices modulo %lu ===\n", p_val);

    /* Eficiencia O(p): Se itera y desde 0 hasta (p - 1)/2.
     * Para y = 0: raiz = 0 (1 raiz).
     * Para y > 0: r = y^2 mod p, con raices {y, p - y} (2 raices distintas). */
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
```

#### Explicación del Funcionamiento:
1. **Fundamento Teórico:** En un campo finito $\mathbb{F}_p$ con $p$ primo impar, existen exactamente $\frac{p - 1}{2}$ residuos cuadráticos no nulos, más el residuo trivial $0$, dando un total de $\frac{p - 1}{2} + 1$ residuos cuadráticos.
2. **Complejidad $O(p)$:** En lugar de probar todos los elementos de $0$ a $p-1$ buscando si tienen raíz cuadrada ($O(p^2)$), iteramos $y \in [0, (p-1)/2]$ y calculamos directamente $r \equiv y^2 \pmod p$.
3. **Determinación de Raíces:** Por propiedades de congruencias, si $y^2 \equiv r \pmod p$, entonces $(-y)^2 \equiv (p - y)^2 \equiv r \pmod p$. Por ende, para cada $r \neq 0$, las dos únicas raíces en $\mathbb{Z}_p$ son $y$ y $p - y$.
4. **Búsqueda en $O(1)$:** La estructura `qr_table_t` indexa directamente en la posición `table->entries[r]`, lo que permite consultas en tiempo constante $O(1)$ para la búsqueda de puntos racionales.

---

### 2.2. Ejercicio 1.2: Puntos Racionales de una Curva Elíptica y Exportación a CSV

#### Objetivo:
Diseñar e implementar una función que reciba $p > 3$ y los parámetros $a, b \in \mathbb{Z}_p$ de una curva elíptica no singular $y^2 \equiv x^3 + ax + b \pmod p$. Utilizar la función del ejercicio previo para encontrar y contar los puntos racionales, representándolos en coordenadas de 3 dimensiones $(x, y, z)$ ($z = 1$ para puntos afines y $(0, 1, 0)$ para el punto al infinito $\mathcal{O}$) y exportándolos a un archivo de texto/CSV.

#### Bloque de Código (`elipt_curve.c`):

```c
point_t* elipar_rational_points(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points) {
    if (num_points != NULL) *num_points = 0;

    if (mpz_cmp_ui(p, 3) <= 0) return NULL;

    /* Validacion de curva no singular: 4a^3 + 27b^2 != 0 (mod p) */
    if (elipar_is_singular(a, b, p)) {
        gmp_fprintf(stderr, "Error: Curva eliptica singular (4a^3 + 27b^2 = 0 mod %Zd).\n", p);
        return NULL;
    }

    unsigned long p_val = mpz_get_ui(p);
    qr_table_t* qr_table = elipar_quadratic_residue(p);
    if (qr_table == NULL) return NULL;

    /* Maximo 2p + 1 puntos posibles (incluyendo O) */
    size_t max_capacity = 2 * (size_t)p_val + 1;
    point_t* points = (point_t*)malloc(sizeof(point_t) * max_capacity);
    for (size_t i = 0; i < max_capacity; i++) point_init(&points[i]);

    size_t count = 0;

    /* 1. Punto al infinito en coordenadas de 3 dimensiones: (0, 1, 0) */
    point_set_infinity(&points[count]);
    count++;

    /* 2. Busqueda de puntos afines (x, y, 1) */
    mpz_t mod_a, mod_b, x3, ax, rhs;
    mpz_inits(mod_a, mod_b, x3, ax, rhs, NULL);
    mpz_mod(mod_a, a, p);
    mpz_mod(mod_b, b, p);

    for (unsigned long x = 0; x < p_val; x++) {
        mpz_t x_mpz;
        mpz_init_set_ui(x_mpz, x);

        /* rhs = x^3 + ax + b mod p */
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

    /* Ajuste exacto de memoria */
    for (size_t i = count; i < max_capacity; i++) point_clear(&points[i]);
    point_t* resized = (point_t*)realloc(points, sizeof(point_t) * count);
    if (resized != NULL) points = resized;

    if (num_points != NULL) *num_points = count;
    return points;
}

int elipar_points_to_csv(const char* filename, const point_t* points, const size_t num_points, 
                         const mpz_t a, const mpz_t b, const mpz_t p) {
    FILE* file = fopen(filename, "w");
    if (!file) return 1;

    gmp_fprintf(file, ",p,%Zd\n", p);
    gmp_fprintf(file, ",a,%Zd\n", a);
    gmp_fprintf(file, ",b,%Zd\n", b);
    fprintf(file, ",count,%zu\n", num_points);
    fprintf(file, "x,y,z\n");

    for (size_t i = 0; i < num_points; i++) {
        gmp_fprintf(file, "%Zd,%Zd,%Zd\n", points[i].x, points[i].y, points[i].z);
    }

    fclose(file);
    return 0;
}
```

#### Explicación del Funcionamiento:
1. **Validación de No-Singularidad:** Calcula el discriminante $\Delta = 4a^3 + 27b^2 \pmod p$. Si $\Delta \equiv 0$, la curva posee una cúspide o un nodo de auto-intersección y carece de estructura de grupo algebraico abeliano; la función rechaza la curva de forma preventiva.
2. **Punto al Infinito:** Se incluye obligatoriamente el elemento neutro del grupo elíptico $\mathcal{O}$, representado según la especificación con $z = 0$, es decir, $(0, 1, 0)$.
3. **Puntos Afines:** Para cada $x \in [0, p-1]$, se evalúa el polinomio cúbico $rhs = x^3 + ax + b \pmod p$. Mediante la tabla de residuos cuadráticos previamente generada, se consulta en tiempo $O(1)$ si $rhs$ es residuo cuadrático. Si lo es, se asocian sus raíces $y$ ($1$ raíz si $rhs = 0$, $2$ raíces si $rhs > 0$) y se almacenan como puntos $(x, y, 1)$.
4. **Exportación Estructurada:** Genera un archivo CSV que registra en su cabecera los parámetros de la curva ($p, a, b$), el conteo total de puntos y la tabla de coordenadas $(x, y, z)$.

---

### 2.3. Ejercicio 1.3: Programa de Prueba Separado (Sección 1)

En [`main.c`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/main.c), la **Opción 1** ejecuta el Ejercicio 1.1 y la **Opción 2** ejecuta el Ejercicio 1.2 de forma aislada e interactiva, permitiendo imprimir en consola, exportar a CSV o ambos.

---

## 3. Sección 2: Aritmética de Curvas Elípticas con GMP (Código y Explicación)

Para manejar enteros de tamaño arbitrario (hasta 2048 bits o superiores), el tipo `point_t` y todas las operaciones se adaptaron utilizando la biblioteca **GNU MP (GMP)**:

```c
typedef struct {
    mpz_t x;
    mpz_t y;
    mpz_t z; /* z = 1 (punto afin normal), z = 0 (punto al infinito O = (0, 1, 0)) */
} point_t;
```

Además, se incorporó un parser de expresiones matemáticas (`parse_mpz_expression`) que permite al usuario ingresar directamente números en formato de potencias como `2^31 - 1`, `2^61 - 1`, `2^255 - 19` o `(2^16) + 1`.

---

### 3.1. Ejercicio 2.1: Encontrar Curva Elíptica No-Singular en $\text{GF}(p)$ de $n$ Bits

#### Objetivo:
Diseñar e implementar una función que reciba la longitud en bits $n$ de un número primo $p$, genere aleatoriamente un número primo de $n$ bits y encuentre aleatoriamente los valores $a, b \in \mathbb{Z}_p$ de una curva no singular $y^2 = x^3 + ax + b \pmod p$.

#### Bloque de Código (`elipt_curve.c`):

```c
int elipar_generate_curve(mpz_t p, mpz_t a, mpz_t b, unsigned int n_bits, gmp_randstate_t state) {
    if (n_bits < 3) {
        fprintf(stderr, "Error: La longitud en bits debe ser al menos 3.\n");
        return -1;
    }

    /* 1. Generar primo aleatorio p de exactamente n_bits */
    do {
        mpz_urandomb(p, state, n_bits);
        mpz_setbit(p, n_bits - 1); /* Garantiza que tenga exactamente n bits */
        mpz_setbit(p, 0);          /* Garantiza que sea impar */
        mpz_nextprime(p, p);       /* Busca el siguiente primo probable */
    } while (mpz_sizeinbase(p, 2) != n_bits || mpz_cmp_ui(p, 3) <= 0);

    /* 2. Encontrar valores aleatorios a, b en [0, p-1] con Delta != 0 mod p */
    do {
        mpz_urandomm(a, state, p);
        mpz_urandomm(b, state, p);
    } while (elipar_is_singular(a, b, p));

    return 0;
}
```

#### Explicación del Funcionamiento:
1. **Generación del Primo:** Con `mpz_urandomb` se obtiene una secuencia uniforme de $n$ bits. Se fuerza el bit más significativo (bit $n-1$) en $1$ para asegurar que el valor pertenezca al rango $[2^{n-1}, 2^n - 1]$, y el bit menos significativo en $1$ para hacerlo impar.
2. **Primalidad:** `mpz_nextprime` aplica pruebas de primalidad probabilísticas (incluyendo divisiones tentativas y el test de Miller-Rabin). Si el primo rebasa los $n$ bits, el bucle repite el proceso.
3. **Generación de Parámetros $a, b$:** Se muestrean aleatoriamente $a, b \in \mathbb{Z}_p$ usando `mpz_urandomm`. Se evalúa el discriminante $\Delta = 4a^3 + 27b^2 \pmod p$. La probabilidad de que una curva aleatoria sobre $\mathbb{F}_p$ sea singular es despreciable ($\approx 1/p$), por lo que el bucle converge casi instantáneamente (incluso en 2048 bits toma menos de $0.06$ segundos).

---

### 3.2. Ejercicio 2.2: Suma de Puntos $P + Q$ donde $P \neq \pm Q$

#### Objetivo:
Diseñar e implementar una función que reciba $a, b, p, P, Q$, verifique que $P$ y $Q$ pertenezcan a la curva elíptica $y^2 = x^3 + ax + b \pmod p$, use 3 coordenadas para representarlos y retorne el resultado del punto suma $P + Q$.

#### Bloque de Código (`elipt_curve.c`):

```c
int elipar_point_add(point_t* R, const point_t* P, const point_t* Q, 
                     const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL || Q == NULL) return -1;

    /* 1. Verificacion de pertenencia a la curva */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }
    if (!elipar_is_point_on_curve(Q, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto Q no pertenece a la curva.\n");
        return -1;
    }

    /* 2. Casos con el punto al infinito */
    if (point_is_infinity(P)) { point_set(R, Q); return 0; }
    if (point_is_infinity(Q)) { point_set(R, P); return 0; }

    mpz_t px, py, qx, qy;
    mpz_inits(px, py, qx, qy, NULL);
    mpz_mod(px, P->x, p); mpz_mod(py, P->y, p);
    mpz_mod(qx, Q->x, p); mpz_mod(qy, Q->y, p);

    /* 3. Caso x_P == x_Q */
    if (mpz_cmp(px, qx) == 0) {
        mpz_t neg_qy;
        mpz_init(neg_qy);
        mpz_sub(neg_qy, p, qy);
        mpz_mod(neg_qy, neg_qy, p);

        /* Si y_P == -y_Q mod p => P = -Q => P + Q = O */
        if (mpz_cmp(py, neg_qy) == 0) {
            point_set_infinity(R);
            mpz_clear(neg_qy);
            mpz_clears(px, py, qx, qy, NULL);
            return 0;
        }
        mpz_clear(neg_qy);

        /* Si y_P == y_Q mod p => P == Q => Duplicacion de punto */
        if (mpz_cmp(py, qy) == 0) {
            mpz_clears(px, py, qx, qy, NULL);
            return elipar_point_double(R, P, a, b, p);
        }
    }

    /* 4. Formula de adicion para P != +-Q */
    mpz_t dy, dx, inv_dx, lambda, x3, y3, tmp;
    mpz_inits(dy, dx, inv_dx, lambda, x3, y3, tmp, NULL);

    /* dy = y_2 - y_1 mod p */
    mpz_sub(dy, qy, py);
    mpz_mod(dy, dy, p);

    /* dx = x_2 - x_1 mod p */
    mpz_sub(dx, qx, px);
    mpz_mod(dx, dx, p);

    /* lambda = dy * dx^(-1) mod p */
    if (mpz_invert(inv_dx, dx, p) == 0) {
        mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
        return -1;
    }
    mpz_mul(lambda, dy, inv_dx);
    mpz_mod(lambda, lambda, p);

    /* x3 = lambda^2 - x_1 - x_2 mod p */
    mpz_powm_ui(x3, lambda, 2, p);
    mpz_sub(x3, x3, px);
    mpz_sub(x3, x3, qx);
    mpz_mod(x3, x3, p);

    /* y3 = lambda*(x_1 - x3) - y_1 mod p */
    mpz_sub(tmp, px, x3);
    mpz_mul(y3, lambda, tmp);
    mpz_sub(y3, y3, py);
    mpz_mod(y3, y3, p);

    /* Guardar resultado en R con z = 1 */
    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set_ui(R->z, 1);

    mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
    return 0;
}
```

#### Explicación del Funcionamiento:
1. **Comprobación Preliminar:** La función `elipar_is_point_on_curve` evalúa si $y_P^2 \equiv x_P^3 + ax_P + b \pmod p$. Si alguno de los puntos no satisface la curva, la función aborta con un mensaje de error y código `-1`.
2. **Propiedades de Grupo:**
   * $P + \mathcal{O} = P$ y $\mathcal{O} + Q = Q$.
   * Si $x_P = x_Q$ y $y_P \equiv -y_Q \pmod p$, la recta que une los puntos es vertical y converge en el punto al infinito $\mathcal{O} = (0, 1, 0)$.
3. **Cálculo de la Pendiente $\lambda$:** La recta secante tiene pendiente $\lambda = \frac{y_2 - y_1}{x_2 - x_1} \pmod p$. El inverso modular de $(x_2 - x_1)$ se calcula mediante el algoritmo de Euclides extendido implementado en `mpz_invert`.
4. **Nuevo Punto:** La intersección con la curva cúbica determina $x_3 = \lambda^2 - x_1 - x_2 \pmod p$ y $y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$. Se fija $z_3 = 1$.

---

### 3.3. Ejercicio 2.3: Duplicación de Punto $2P$

#### Objetivo:
Diseñar e implementar una función que reciba $a, b, p, P$, verifique que $P$ pertenezca a la curva elíptica $y^2 = x^3 + ax + b \pmod p$, use 3 coordenadas para representarlo y retorne el resultado de la duplicación $2P$.

#### Bloque de Código (`elipt_curve.c`):

```c
int elipar_point_double(point_t* R, const point_t* P, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL) return -1;

    /* 1. Verificacion de pertenencia a la curva */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: El punto P no pertenece a la curva.\n");
        return -1;
    }

    /* 2. Caso P = O => 2P = O */
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return 0;
    }

    mpz_t px, py, mod_a;
    mpz_inits(px, py, mod_a, NULL);
    mpz_mod(px, P->x, p);
    mpz_mod(py, P->y, p);
    mpz_mod(mod_a, a, p);

    /* 3. Si y == 0 mod p, la tangente es vertical => 2P = O */
    if (mpz_cmp_ui(py, 0) == 0) {
        point_set_infinity(R);
        mpz_clears(px, py, mod_a, NULL);
        return 0;
    }

    /* 4. Formula de recta tangente en P:
     * lambda = (3*x1^2 + a) / (2*y1) mod p */
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

    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set_ui(R->z, 1);

    mpz_clears(num, den, inv_den, lambda, x3, y3, tmp, px, py, mod_a, NULL);
    return 0;
}
```

#### Explicación del Funcionamiento:
1. **Derivación Implícita de la Tangente:** Derivando la ecuación $y^2 = x^3 + ax + b$ respecto a $x$:
   $$2y \frac{dy}{dx} = 3x^2 + a \implies \lambda = \frac{dy}{dx} = \frac{3x_1^2 + a}{2y_1} \pmod p$$
2. **Tangente Vertical:** Si $y_1 \equiv 0 \pmod p$, la recta tangente es vertical y no vuelve a intersectar la curva en ningún punto finito; por tanto, $2P = \mathcal{O} = (0, 1, 0)$.
3. **Cálculo de Coordenadas:** Sustituyendo la tangente en la ecuación cúbica se obtiene $x_3 = \lambda^2 - 2x_1 \pmod p$ y $y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$.

---

### 3.4. Ejercicio 2.4: Programa de Prueba Separado (Sección 2)

En [`main.c`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/main.c), las opciones del menú permiten probar cada función por separado:
* **Opción 3:** Probar generación de curva no singular para cualquier $n$ bits.
* **Opción 4:** Probar suma de puntos $P + Q$ ingresando puntos en 3 coordenadas y aceptando formato de potencias (ej. `2^31 - 1`).
* **Opción 5:** Probar duplicación de punto $2P$.

---

## 4. Sección 3: Respuestas a las Preguntas del Laboratorio

### 4.1. Pregunta 1: Tres Curvas No Singulares con $3 \le p < 10,000$ y sus Gráficas

Se generaron y analizaron tres curvas elípticas en distintos campos finitos, exportando los puntos a archivos CSV y generando las gráficas de dispersión de sus puntos afines:

| Curva | Parámetros ($p, a, b$) | Condición $\Delta \not\equiv 0 \pmod p$ | Total de Puntos | Puntos Afines | Archivo CSV | Gráfica Generada |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Curva 1** | $p = 31, a = 11, b = 5$ | $\Delta \equiv 21 \not\equiv 0$ | $32$ | $31$ | [`curva1_p31.csv`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/curva1_p31.csv) | [`grafica_curva1_p31.png`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/grafica_curva1_p31.png) |
| **Curva 2** | $p = 97, a = 2, b = 3$ | $\Delta \equiv 81 \not\equiv 0$ | $100$ | $99$ | [`curva2_p97.csv`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/curva2_p97.csv) | [`grafica_curva2_p97.png`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/grafica_curva2_p97.png) |
| **Curva 3** | $p = 251, a = 3, b = 7$ | $\Delta \equiv 176 \not\equiv 0$ | $280$ | $279$ | [`curva3_p251.csv`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/curva3_p251.csv) | [`grafica_curva3_p251.png`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/grafica_curva3_p251.png) |

#### Análisis de las Gráficas:
1. **Simetría:** En las tres gráficas se observa claramente la simetría horizontal respecto al eje $y = p/2$. Para cada punto $(x, y)$, existe su inverso $(x, p - y)$.
2. **Teorema de Hasse:** El número de puntos racionales $\#E(\mathbb{F}_p)$ satisface rigurosamente la cota de Hasse:
   $$| \#E(\mathbb{F}_p) - (p + 1) | \le 2\sqrt{p}$$
   * Para $p = 31$: $p + 1 = 32$, $\#E = 32 \implies |32 - 32| = 0 \le 2\sqrt{31} \approx 11.13$.
   * Para $p = 97$: $p + 1 = 98$, $\#E = 100 \implies |100 - 98| = 2 \le 2\sqrt{97} \approx 19.69$.
   * Para $p = 251$: $p + 1 = 252$, $\#E = 280 \implies |280 - 252| = 28 \le 2\sqrt{251} \approx 31.68$.

---

### 4.2. Pregunta 2: Primos y Curvas No Singulares para 16, 32, 64, 512, 1024 y 2048 Bits

El archivo independiente [`curvas_aleatorias.md`](file:///C:/Users/gzaragozag1800/Documents/GitHub/SelectedTopicsCripto-2027-01/lab%2001/curvas_aleatorias.md) contiene la totalidad de los números y parámetros generados. A continuación se presenta la tabla resumen de resultados:

| Tamaño | Primo $p$ (muestra / inicio) | Coeficiente $a$ | Coeficiente $b$ | $\Delta \not\equiv 0$ | Tiempo de Cómputo |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **16 bits** | `45077` | `30531` | `36749` | Sí | `0.0000 s` |
| **32 bits** | `2520061931` | `1842367674` | `1527943391` | Sí | `0.0000 s` |
| **64 bits** | `17940631871677364777` | `5071917366060802725` | `5797321028269090453` | Sí | `0.0000 s` |
| **512 bits** | `94877478991649...82253` | `6931458096...91354` | `1043400530...91895` | Sí | `0.0000 s` |
| **1024 bits**| `17772478388385...83483` | `1019931614...73779` | `1245759029...75962` | Sí | `0.0080 s` |
| **2048 bits**| `23053419987883...77707` | `1730189069...1225179`| `1663765351...13091` | Sí | `0.0590 s` |

---

### 4.3. Pregunta 3: Cómputo de $P + Q$, $2P$ y $2Q$ (Incisos a, b, c, d)

Se evaluaron automáticamente los cuatro incisos con verificación de pertenencia a la curva:

#### Inciso a)
* **Ecuación:** $y^2 = x^3 + x + 1 \pmod{65537}$
* **Puntos dados:** $P = (49606, 64426, 1)$, $Q = (2565, 62370, 1)$
* **Pertenencia:** $P \in E$ (Válido), $Q \in E$ (Válido)
* **Resultados:**
  * **$P + Q = (43190, 62760, 1)$** $\in E$
  * **$2P = (27838, 52313, 1)$** $\in E$
  * **$2Q = (11605, 53046, 1)$** $\in E$

#### Inciso b)
* **Ecuación:** $y^2 = x^3 + 30x + 97 \pmod{4294967311}$
* **Puntos dados:** $P = (433318550, 1866632789, 1)$, $Q = (408186704, 4022951807, 1)$
* **Pertenencia:** $P \in E$ (Válido), $Q \in E$ (Válido)
* **Resultados:**
  * **$P + Q = (1365729123, 1751038107, 1)$** $\in E$
  * **$2P = (4068212755, 1475533388, 1)$** $\in E$
  * **$2Q = (1572879236, 1387343506, 1)$** $\in E$

#### Inciso c)
* **Ecuación:** $y^2 = x^3 + 125x + 2 \pmod{2^{31} - 1}$ donde $p = 2147483647$ (Primo de Mersenne $M_{31}$)
* **Puntos dados:** $P = (1506532484, 1041296099, 1)$, $Q = (1624813594, 253477454, 1)$
* **Pertenencia:** $P \in E$ (Válido), $Q \in E$ (Válido)
* **Resultados:**
  * **$P + Q = (438842645, 2065604505, 1)$** $\in E$
  * **$2P = (742142419, 1577310052, 1)$** $\in E$
  * **$2Q = (1125939014, 778061759, 1)$** $\in E$

#### Inciso d)
* **Ecuación:** $y^2 = x^3 + x + 1300 \pmod{2^{61} - 1}$ donde $p = 2305843009213693951$ (Primo de Mersenne $M_{61}$)
* **Puntos dados:**  
  $P = (1317571598731990128, 494998261481053431, 1)$  
  $Q = (590181223958911612, 1863749232038030155, 1)$
* **Pertenencia:** $P \in E$ (Válido), $Q \in E$ (Válido)
* **Resultados:**
  * **$P + Q = (2223280671137397525, 2193609183055342937, 1)$** $\in E$
  * **$2P = (492215062149154878, 1699466406640207765, 1)$** $\in E$
  * **$2Q = (1425847782956718139, 2293499795315943298, 1)$** $\in E$

---

## 5. Declaración de Uso de Inteligencia Artificial (AI Disclosure)

De acuerdo con las instrucciones de la página 3 del documento del laboratorio:
> *"If you use any AI for some parts of your code, please give the name of AI you used. Also you must indicate what source code was given by the AI. Justify why you need to use it."*

1. **Nombre de la IA utilizada:** Google Antigravity / Gemini 3.8 Flash.
2. **Código y componentes asistidos por IA:**
   * Adaptación de las funciones previas basadas en `int` para emplear los tipos y operadores de precisión múltiple de GNU MP (`mpz_t`, `mpz_init`, `mpz_clear`, `mpz_mod`, `mpz_powm_ui`, `mpz_invert`, `gmp_printf`).
   * Implementación del analizador léxico/sintáctico de potencias (`parse_mpz_expression`), que permite ingresar expresiones como `2^31 - 1` y `2^61 - 1` directamente desde la interfaz por consola.
   * Automatización de las suites de prueba de la Sección 3 (batería de incisos a-d y curvas de 16 a 2048 bits).
   * Script de graficación vectorial de puntos racionales (`plot_curve.ps1`).
3. **Justificación:**
   * La aritmética modular en curvas elípticas criptográficas involucra números de 31, 61, 512, 1024 y 2048 bits que superan por órdenes de magnitud los tipos primitivos nativos de 64 bits (`unsigned long long`). El uso de GMP requería una gestión manual rigurosa de memoria para evitar fugas de memoria (*memory leaks*) y asegurar la precisión matemática exacta en inversos modulares y duplicaciones de punto.
   * La implementación del parser de potencias agiliza drásticamente las pruebas interactivas de laboratorio al no requerir que el usuario calcule y escriba manualmente los valores expandidos de números como $2^{61} - 1$.
