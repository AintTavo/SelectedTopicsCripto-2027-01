# Technical Report - Lab 01: Elliptic Curves

**Instituto Politécnico Nacional**  
**Escuela Superior de Cómputo (ESCOM)**  
**Selected Topics in Cryptography**  
**Session 1: Elliptic Curves** — *September 2026*  

---

## 1. General Information

* **Institution:** Instituto Politécnico Nacional (IPN) - Escuela Superior de Cómputo (ESCOM)
* **Course:** Selected Topics in Cryptography
* **Topic:** Quadratic Residues, Rational Points, and Elliptic Curve Arithmetic over Finite Fields $\text{GF}(p)$ with Big Integers (GMP)
* **Student:** *[Student Name]*
* **Student ID (Boleta):** *[Student ID Number]*
* **Date:** September 2026
* **Language & Toolchain:** C (GCC MinGW-w64 compiler and GNU Multiple Precision Arithmetic Library / GMP 6.3.0)

---

## 2. Section 1: Preliminary Functions (Source Code & Explanation)

### 2.1. Exercise 1.1: Quadratic Residues and Square Roots Modulo $p > 3$

#### Objective:
Design and implement a function that receives as a parameter a prime number $p > 3$, prints all quadratic residues modulo $p$ ($\text{QR}_p$), and for each quadratic residue prints its square roots.

#### Source Code (`elipt_curve.c` & `elipt_curve.h`):

```c
/* Hash table entry structure for quadratic residues */
typedef struct qr_entry {
    unsigned long key;            /* Quadratic residue (hash key) */
    unsigned long roots[2];       /* Associated square roots */
    int root_count;               /* Number of roots (1 for 0, 2 for r > 0) */
    bool is_occupied;             /* Bucket occupancy flag */
} qr_entry_t;

typedef struct qr_table {
    qr_entry_t* entries;          /* Direct-indexed buckets */
    size_t capacity;              /* Table capacity (p) */
    size_t count;                 /* Total count of quadratic residues */
    unsigned long p;              /* Prime modulus */
} qr_table_t;

qr_table_t* elipar_quadratic_residue(const mpz_t p) {
    if (mpz_cmp_ui(p, 3) <= 0) {
        fprintf(stderr, "Error(quad): Invalid number, p must be greater than 3.\n");
        return NULL;
    }

    if (mpz_cmp_ui(p, 200000) > 0) {
        gmp_fprintf(stderr, "Warning(quad): p = %Zd is too large to list in RAM.\n", p);
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

    printf("=== Quadratic residues and roots modulo %lu ===\n", p_val);

    /* O(p) Efficiency: Iterate y from 0 to (p - 1)/2.
     * - y = 0  => r = 0, root = {0}
     * - y > 0  => r = y^2 mod p, roots = {y, p - y} */
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
            printf("Quadratic residue: %-6lu | Roots: { %lu }\n", r, entry->roots[0]);
        } else {
            entry->roots[0] = (unsigned long)y;
            entry->roots[1] = p_val - (unsigned long)y;
            entry->root_count = 2;
            printf("Quadratic residue: %-6lu | Roots: { %lu, %lu }\n", r, entry->roots[0], entry->roots[1]);
        }
        table->count++;
    }

    printf("Total quadratic residues found: %zu\n\n", table->count);
    return table;
}
```

#### Brief Explanation of How It Works:
1. **Mathematical Basis:** In any finite field $\mathbb{F}_p$ where $p > 2$ is prime, there are exactly $\frac{p - 1}{2}$ non-zero quadratic residues and $1$ trivial residue ($0$), yielding a total of $\frac{p - 1}{2} + 1$ quadratic residues.
2. **Computational Complexity $O(p)$:** Rather than testing every element in $[0, p-1]$ for square roots (which would require $O(p^2)$), the algorithm directly iterates $y \in [0, (p-1)/2]$ and computes $r \equiv y^2 \pmod p$.
3. **Square Roots Determination:** By modular arithmetic congruences, if $y^2 \equiv r \pmod p$, then $(-y)^2 \equiv (p - y)^2 \equiv r \pmod p$. Therefore, for each $r > 0$, the exact pair of distinct square roots in $\mathbb{Z}_p$ is $\{y, p - y\}$.
4. **$O(1)$ Hash Table Lookup:** Entries are directly indexed by their residue value `table->entries[r]`. This allows subsequent elliptic curve point searches to verify quadratic residues and retrieve square roots in $O(1)$ constant time.

---

### 2.2. Exercise 1.2: Rational Points of an Elliptic Curve and Export to File

#### Objective:
Design and implement a function that receives a prime number $p > 3$ and parameters $a, b \in \mathbb{Z}_p$ of a non-singular elliptic curve $y^2 \equiv x^3 + ax + b \pmod p$. Use the quadratic residue function to find and count the rational points of the curve, representing each point in projective coordinates $(x, y, z)$ ($z = 1$ for affine points and $(0, 1, 0)$ for the point at infinity $\mathcal{O}$), and store $p, a, b$ and the rational points in a CSV/text file.

#### Source Code (`elipt_curve.c`):

```c
point_t* elipar_rational_points(const mpz_t a, const mpz_t b, const mpz_t p, size_t* num_points) {
    if (num_points != NULL) *num_points = 0;

    if (mpz_cmp_ui(p, 3) <= 0) return NULL;

    /* Non-singularity verification: 4a^3 + 27b^2 != 0 (mod p) */
    if (elipar_is_singular(a, b, p)) {
        gmp_fprintf(stderr, "Error: Singular elliptic curve (4a^3 + 27b^2 = 0 mod %Zd).\n", p);
        return NULL;
    }

    unsigned long p_val = mpz_get_ui(p);
    qr_table_t* qr_table = elipar_quadratic_residue(p);
    if (qr_table == NULL) return NULL;

    /* Maximum capacity: 2p + 1 points (including O) */
    size_t max_capacity = 2 * (size_t)p_val + 1;
    point_t* points = (point_t*)malloc(sizeof(point_t) * max_capacity);
    for (size_t i = 0; i < max_capacity; i++) point_init(&points[i]);

    size_t count = 0;

    /* 1. Point at infinity in projective coordinates: (0, 1, 0) */
    point_set_infinity(&points[count]);
    count++;

    /* 2. Affine points search (x, y, 1) */
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

    /* Free unused allocated positions */
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

#### Brief Explanation of How It Works:
1. **Non-Singularity Check:** The discrete discriminant $\Delta = 4a^3 + 27b^2 \pmod p$ is computed. If $\Delta \equiv 0$, the curve has a cusp or node (self-intersection) and lacks an abelian group structure; the function detects this and rejects the curve.
2. **Point at Infinity:** The identity element $\mathcal{O}$ is explicitly added first, stored with $z = 0$ as $(0, 1, 0)$.
3. **Affine Points Evaluation:** For every coordinate $x \in [0, p-1]$, the cubic polynomial $\text{rhs} = x^3 + ax + b \pmod p$ is evaluated. By querying the quadratic residue table in $O(1)$ time, if $\text{rhs}$ is a quadratic residue, its corresponding roots $y$ are extracted ($1$ root if $\text{rhs} = 0$, $2$ roots if $\text{rhs} > 0$) and stored as $(x, y, 1)$.
4. **Structured CSV Export:** The output file stores the curve metadata ($p, a, b$), total point count, and the $(x, y, z)$ coordinates table matching the lab specification.

---

### 2.3. Exercise 1.3: Program to Test Preliminary Functions Separately

The main program (`main.c`) provides an interactive menu where:
* **Option 1** executes Exercise 1.1 (Quadratic Residues and Roots).
* **Option 2** executes Exercise 1.2 (Rational Points Enumeration and CSV Export).

---

## 3. Section 2: Elliptic Curve Arithmetic with GMP (Source Code & Explanation)

### 3.1. Exercise 2.1: Find a Non-Singular Elliptic Curve in $\text{GF}(p)$ of $n$ Bits

#### Objective:
Design and implement a function that receives the bit-length $n$ of a prime number $p$, randomly generates an $n$-bit prime number $p$, and randomly finds values $a, b \in \mathbb{Z}_p$ for a non-singular curve $y^2 = x^3 + ax + b \pmod p$.

#### Source Code (`elipt_curve.c`):

```c
int elipar_generate_curve(mpz_t p, mpz_t a, mpz_t b, unsigned int n_bits, gmp_randstate_t state) {
    if (n_bits < 3) {
        fprintf(stderr, "Error: Bit length must be at least 3.\n");
        return -1;
    }

    /* 1. Randomly generate an n-bit prime p */
    do {
        mpz_urandomb(p, state, n_bits);
        mpz_setbit(p, n_bits - 1); /* Force the MSB to guarantee exactly n bits */
        mpz_setbit(p, 0);          /* Ensure the number is odd */
        mpz_nextprime(p, p);       /* Probabilistic prime generation */
    } while (mpz_sizeinbase(p, 2) != n_bits || mpz_cmp_ui(p, 3) <= 0);

    /* 2. Find random a, b in [0, p-1] such that Delta != 0 mod p */
    do {
        mpz_urandomm(a, state, p);
        mpz_urandomm(b, state, p);
    } while (elipar_is_singular(a, b, p));

    return 0;
}
```

#### Brief Explanation of How It Works:
1. **$n$-bit Prime Generation:** The function uses `mpz_urandomb` to sample an $n$-bit integer uniformly. It sets bit $n-1$ to 1 (ensuring the value lies in $[2^{n-1}, 2^n - 1]$) and bit 0 to 1 (making it odd). It then invokes `mpz_nextprime`, which uses trial divisions and Miller-Rabin probabilistic tests to find the next prime. If it overflows $n$ bits, the loop regenerates.
2. **Coefficients Selection ($a, b$):** Random values $a, b \in [0, p-1]$ are sampled with `mpz_urandomm`. The function verifies non-singularity by evaluating $\Delta = 4a^3 + 27b^2 \pmod p \neq 0$. Singular curves are rejected. Because singular curves have negligible density ($\sim 1/p$), finding valid parameters completes almost instantly even for 2048 bits.

---

### 3.2. Exercise 2.2: Point Addition $P + Q$ where $P \neq \pm Q$

#### Objective:
Design and implement a function to compute point addition $P + Q$ for $P \neq \pm Q$. Verify that $P$ and $Q$ belong to the curve $y^2 = x^3 + ax + b \pmod p$. Use three coordinates $(x, y, z)$ to represent each point, receive parameters $a, b, p, P, Q$, and return the addition result.

#### Source Code (`elipt_curve.c`):

```c
int elipar_point_add(point_t* R, const point_t* P, const point_t* Q, 
                     const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL || Q == NULL) return -1;

    /* 1. Point membership validation */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: Point P does not belong to the curve.\n");
        return -1;
    }
    if (!elipar_is_point_on_curve(Q, a, b, p)) {
        gmp_fprintf(stderr, "Error: Point Q does not belong to the curve.\n");
        return -1;
    }

    /* 2. Identity element handling */
    if (point_is_infinity(P)) { point_set(R, Q); return 0; }
    if (point_is_infinity(Q)) { point_set(R, P); return 0; }

    mpz_t px, py, qx, qy;
    mpz_inits(px, py, qx, qy, NULL);
    mpz_mod(px, P->x, p); mpz_mod(py, P->y, p);
    mpz_mod(qx, Q->x, p); mpz_mod(qy, Q->y, p);

    /* 3. Handle identical x coordinates */
    if (mpz_cmp(px, qx) == 0) {
        mpz_t neg_qy;
        mpz_init(neg_qy);
        mpz_sub(neg_qy, p, qy);
        mpz_mod(neg_qy, neg_qy, p);

        /* P = -Q => P + Q = O */
        if (mpz_cmp(py, neg_qy) == 0) {
            point_set_infinity(R);
            mpz_clear(neg_qy);
            mpz_clears(px, py, qx, qy, NULL);
            return 0;
        }
        mpz_clear(neg_qy);

        /* P = Q => Delegate to point doubling */
        if (mpz_cmp(py, qy) == 0) {
            mpz_clears(px, py, qx, qy, NULL);
            return elipar_point_double(R, P, a, b, p);
        }
    }

    /* 4. Addition formula for P != +-Q:
     * lambda = (y_2 - y_1) / (x_2 - x_1) mod p */
    mpz_t dy, dx, inv_dx, lambda, x3, y3, tmp;
    mpz_inits(dy, dx, inv_dx, lambda, x3, y3, tmp, NULL);

    mpz_sub(dy, qy, py);
    mpz_mod(dy, dy, p);

    mpz_sub(dx, qx, px);
    mpz_mod(dx, dx, p);

    if (mpz_invert(inv_dx, dx, p) == 0) {
        mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
        return -1;
    }
    mpz_mul(lambda, dy, inv_dx);
    mpz_mod(lambda, lambda, p);

    /* x_3 = lambda^2 - x_1 - x_2 mod p */
    mpz_powm_ui(x3, lambda, 2, p);
    mpz_sub(x3, x3, px);
    mpz_sub(x3, x3, qx);
    mpz_mod(x3, x3, p);

    /* y_3 = lambda * (x_1 - x_3) - y_1 mod p */
    mpz_sub(tmp, px, x3);
    mpz_mul(y3, lambda, tmp);
    mpz_sub(y3, y3, py);
    mpz_mod(y3, y3, p);

    /* Store destination point with z = 1 */
    mpz_set(R->x, x3);
    mpz_set(R->y, y3);
    mpz_set_ui(R->z, 1);

    mpz_clears(dy, dx, inv_dx, lambda, x3, y3, tmp, px, py, qx, qy, NULL);
    return 0;
}
```

#### Brief Explanation of How It Works:
1. **Verification of Curve Membership:** Before executing arithmetic, `elipar_is_point_on_curve` verifies that $y^2 \equiv x^3 + ax + b \pmod p$. If either point is invalid, the operation is aborted.
2. **Boundary and Group Law Conditions:** If $P = \mathcal{O}$, $P + Q = Q$. If $P = -Q$ ($x_P = x_Q$ and $y_P \equiv -y_Q \pmod p$), the secant line is vertical and the sum equals $\mathcal{O} = (0, 1, 0)$.
3. **Slope Calculation:** The slope of the secant line through $P$ and $Q$ is computed as $\lambda \equiv (y_2 - y_1)(x_2 - x_1)^{-1} \pmod p$ using the extended Euclidean algorithm via `mpz_invert`.
4. **Point Coordinates:** Vieta's formulas on the cubic equation yield:
   $$x_3 = \lambda^2 - x_1 - x_2 \pmod p$$
   $$y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$$
   The resulting coordinates are reduced modulo $p$ and returned as $(x_3, y_3, 1)$.

---

### 3.3. Exercise 2.3: Point Doubling $2P$

#### Objective:
Design and implement a function to compute point doubling $2P$. Verify that $P$ belongs to the curve $y^2 = x^3 + ax + b \pmod p$. Use three coordinates $(x, y, z)$ to represent $P$, receive parameters $a, b, p, P$, and return the point doubling result.

#### Source Code (`elipt_curve.c`):

```c
int elipar_point_double(point_t* R, const point_t* P, const mpz_t a, const mpz_t b, const mpz_t p) {
    if (R == NULL || P == NULL) return -1;

    /* 1. Point membership validation */
    if (!elipar_is_point_on_curve(P, a, b, p)) {
        gmp_fprintf(stderr, "Error: Point P does not belong to the curve.\n");
        return -1;
    }

    /* 2. Boundary: P is infinity => 2P = O */
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return 0;
    }

    mpz_t px, py, mod_a;
    mpz_inits(px, py, mod_a, NULL);
    mpz_mod(px, P->x, p);
    mpz_mod(py, P->y, p);
    mpz_mod(mod_a, a, p);

    /* 3. Vertical tangent: y == 0 mod p => 2P = O */
    if (mpz_cmp_ui(py, 0) == 0) {
        point_set_infinity(R);
        mpz_clears(px, py, mod_a, NULL);
        return 0;
    }

    /* 4. Tangent slope formula:
     * lambda = (3*x_1^2 + a) / (2*y_1) mod p */
    mpz_t num, den, inv_den, lambda, x3, y3, tmp;
    mpz_inits(num, den, inv_den, lambda, x3, y3, tmp, NULL);

    /* Numerator: 3*x_1^2 + a mod p */
    mpz_powm_ui(num, px, 2, p);
    mpz_mul_ui(num, num, 3);
    mpz_add(num, num, mod_a);
    mpz_mod(num, num, p);

    /* Denominator: 2*y_1 mod p */
    mpz_mul_ui(den, py, 2);
    mpz_mod(den, den, p);

    if (mpz_invert(inv_den, den, p) == 0) {
        mpz_clears(num, den, inv_den, lambda, x3, y3, tmp, px, py, mod_a, NULL);
        return -1;
    }
    mpz_mul(lambda, num, inv_den);
    mpz_mod(lambda, lambda, p);

    /* x_3 = lambda^2 - 2*x_1 mod p */
    mpz_powm_ui(x3, lambda, 2, p);
    mpz_sub(x3, x3, px);
    mpz_sub(x3, x3, px);
    mpz_mod(x3, x3, p);

    /* y_3 = lambda * (x_1 - x_3) - y_1 mod p */
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

#### Brief Explanation of How It Works:
1. **Implicit Differentiation:** Differentiating the Weierstraß equation $y^2 = x^3 + ax + b$ with respect to $x$ yields $2y \frac{dy}{dx} = 3x^2 + a$. The tangent line slope at $P$ is:
   $$\lambda = \frac{3x_1^2 + a}{2y_1} \pmod p$$
2. **Vertical Tangents:** If $y_1 \equiv 0 \pmod p$, the tangent line is vertical and intersects the curve at infinity; thus $2P = \mathcal{O} = (0, 1, 0)$.
3. **Point Doubling Arithmetic:** The intersection of the tangent with the cubic equation gives $x_3 = \lambda^2 - 2x_1 \pmod p$ and $y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$, returned as $(x_3, y_3, 1)$.

---

### 3.4. Exercise 2.4: Program to Test Section 2 Functions Separately

The CLI in `main.c` provides distinct options to test:
* **Option 3:** Random curve generation for any bit length $n$.
* **Option 4:** Point addition $P + Q$ (accepting power syntax such as `2^31 - 1`).
* **Option 5:** Point doubling $2P$.

---

## 4. Section 3: Answers to Lab Questions

### 4.1. Question 1: Graphs of 3 Non-Singular Curves ($3 \le p < 10,000$)

Three non-singular elliptic curves were generated and their rational points were exported to CSV and plotted:

| Curve | Parameters ($p, a, b$) | $\Delta \not\equiv 0 \pmod p$ | Total Points | Affine Points | CSV File | Plot PNG File |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Curve 1** | $p = 31, a = 11, b = 5$ | $\Delta \equiv 21 \not\equiv 0$ | $32$ | $31$ | `curva1_p31.csv` | `grafica_curva1_p31.png` |
| **Curve 2** | $p = 97, a = 2, b = 3$ | $\Delta \equiv 81 \not\equiv 0$ | $100$ | $99$ | `curva2_p97.csv` | `grafica_curva2_p97.png` |
| **Curve 3** | $p = 251, a = 3, b = 7$ | $\Delta \equiv 176 \not\equiv 0$ | $280$ | $279$ | `curva3_p251.csv` | `grafica_curva3_p251.png` |

#### Theoretical Analysis:
* **Horizontal Symmetry:** Each plot clearly exhibits horizontal symmetry across the line $y = p/2$. For any affine point $(x, y)$, its group inverse is $(x, p - y)$.
* **Hasse's Bound:** The cardinality of each group satisfies Hasse's Theorem: $|\#E(\mathbb{F}_p) - (p + 1)| \le 2\sqrt{p}$.
  * For $p = 31$: $|32 - 32| = 0 \le 2\sqrt{31} \approx 11.13$.
  * For $p = 97$: $|100 - 98| = 2 \le 2\sqrt{97} \approx 19.69$.
  * For $p = 251$: $|280 - 252| = 28 \le 2\sqrt{251} \approx 31.68$.

---

### 4.2. Question 2: Primes and Non-Singular Curves for 16, 32, 64, 512, 1024, and 2048 Bits

The generated parameters are documented in `curvas_aleatorias.md`. Summary table:

| Bit Size | Prime $p$ (sample start/end) | Parameter $a$ | Parameter $b$ | $\Delta \neq 0 \pmod p$ | Generation Time |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **16 bits** | `45077` | `30531` | `36749` | Yes | `0.0000 s` |
| **32 bits** | `2520061931` | `1842367674` | `1527943391` | Yes | `0.0000 s` |
| **64 bits** | `17940631871677364777` | `5071917366060802725` | `5797321028269090453` | Yes | `0.0000 s` |
| **512 bits** | `94877478991649...82253` | `6931458096...91354` | `1043400530...91895` | Yes | `0.0000 s` |
| **1024 bits**| `17772478388385...83483` | `1019931614...73779` | `1245759029...75962` | Yes | `0.0080 s` |
| **2048 bits**| `23053419987883...77707` | `1730189069...1225179`| `1663765351...13091` | Yes | `0.0590 s` |

---

### 4.3. Question 3: Computation of $P + Q, 2P, 2Q$ (Cases a, b, c, d)

All four cases were verified for curve membership and evaluated:

#### Case a)
* **Curve:** $y^2 = x^3 + x + 1 \pmod{65537}$
* **Points:** $P = (49606, 64426, 1)$, $Q = (2565, 62370, 1)$
* **Membership:** $P \in E$ [Valid], $Q \in E$ [Valid]
* **Results:**
  * **$P + Q = (43190, 62760, 1)$** $\in E$
  * **$2P = (27838, 52313, 1)$** $\in E$
  * **$2Q = (11605, 53046, 1)$** $\in E$

#### Case b)
* **Curve:** $y^2 = x^3 + 30x + 97 \pmod{4294967311}$
* **Points:** $P = (433318550, 1866632789, 1)$, $Q = (408186704, 4022951807, 1)$
* **Membership:** $P \in E$ [Valid], $Q \in E$ [Valid]
* **Results:**
  * **$P + Q = (1365729123, 1751038107, 1)$** $\in E$
  * **$2P = (4068212755, 1475533388, 1)$** $\in E$
  * **$2Q = (1572879236, 1387343506, 1)$** $\in E$

#### Case c)
* **Curve:** $y^2 = x^3 + 125x + 2 \pmod{2^{31} - 1}$ where $p = 2147483647$ (Mersenne prime $M_{31}$)
* **Points:** $P = (1506532484, 1041296099, 1)$, $Q = (1624813594, 253477454, 1)$
* **Membership:** $P \in E$ [Valid], $Q \in E$ [Valid]
* **Results:**
  * **$P + Q = (438842645, 2065604505, 1)$** $\in E$
  * **$2P = (742142419, 1577310052, 1)$** $\in E$
  * **$2Q = (1125939014, 778061759, 1)$** $\in E$

#### Case d)
* **Curve:** $y^2 = x^3 + x + 1300 \pmod{2^{61} - 1}$ where $p = 2305843009213693951$ (Mersenne prime $M_{61}$)
* **Points:**  
  $P = (1317571598731990128, 494998261481053431, 1)$  
  $Q = (590181223958911612, 1863749232038030155, 1)$
* **Membership:** $P \in E$ [Valid], $Q \in E$ [Valid]
* **Results:**
  * **$P + Q = (2223280671137397525, 2193609183055342937, 1)$** $\in E$
  * **$2P = (492215062149154878, 1699466406640207765, 1)$** $\in E$
  * **$2Q = (1425847782956718139, 2293499795315943298, 1)$** $\in E$

---

## 5. AI Usage Disclosure (Section 4 Requirement)

In compliance with page 3 of the lab document:
> *"If you use any AI for some parts of your code, please give the name of AI you used. Also you must indicate what source code was given by the AI. Justify why you need to use it."*

1. **Name of AI used:** Google Antigravity / Gemini 3.8 Flash.
2. **Code and modules assisted by AI:**
   * Refactoring the legacy C integer code to use GNU MP (`mpz_t`, `mpz_init`, `mpz_clear`, `mpz_mod`, `mpz_powm_ui`, `mpz_invert`, `gmp_printf`).
   * Implementation of the recursive-descent power expression parser (`parse_mpz_expression`), enabling input of numbers like `2^31 - 1` and `2^61 - 1` directly from the terminal.
   * Automated test harnesses for Section 3 (Cases a-d and generation benchmarks from 16 to 2048 bits).
   * High-resolution point plotting script (`plot_curve.ps1`).
3. **Justification:**
   * Cryptographic elliptic curve parameters (such as $2^{31}-1$, $2^{61}-1$, and 512–2048 bit keys) exceed native C 64-bit integer capacities (`unsigned long long`). Integrating GMP requires meticulous pointer and memory management to prevent leaks and ensure mathematical exactness in modular inverses and point arithmetic.
   * The power expression parser eliminates manual precomputation of large prime expansions during interactive testing.
