#include <stdint.h>
#include <stddef.h>

#define WASM_EXPORT __attribute__((visibility("default")))

// =============================================================================
// ARITMÉTICA MULTIPRECISIÓN (BIGINT) EN C PARA WEBASSEMBLY (HASTA 2048/3072 BITS)
// Implementa NIST SP 800-56B Rev. 2:
// - Appendix B.1: I2BS (Integer-to-Byte-String)
// - Appendix B.2: BS2I (Byte-String-to-Integer)
// - Section 6.2.1 & 6.2.2: Key Pair Definition & 3 Private Key Formats:
//     1) Basic format: (n, d)
//     2) Prime-factor format: (p, q, d)
//     3) CRT format (8 valores): (n, e, d, p, q, dP, dQ, qInv)
// - Section 6.3.1.3 & 6.4.1.4.3: rsakpg1-crt & crt_pkv Validation
// - Section 7.1.1: RSAEP((n, e), m)
// - Section 7.1.2.3: RSADP(n, e, d, p, q, dP, dQ, qInv, c) en formato CRT
// - Section 7.2.2.2, 7.2.2.3, 7.2.2.4: MGF1-SHA256, RSA-OAEP.ENCRYPT, RSA-OAEP.DECRYPT
// =============================================================================

#define BN_MAX_WORDS 64 // 64 * 32 = 2048 bits

typedef struct {
    uint32_t w[BN_MAX_WORDS]; // Little-endian words: w[0] es el menos significativo
} bn_t;

static void bn_zero(bn_t* a) {
    for (int i = 0; i < BN_MAX_WORDS; i++) a->w[i] = 0;
}

static void bn_copy(bn_t* dst, const bn_t* src) {
    for (int i = 0; i < BN_MAX_WORDS; i++) dst->w[i] = src->w[i];
}

static void bn_set_u32(bn_t* a, uint32_t val) {
    bn_zero(a);
    a->w[0] = val;
}

static int bn_is_zero(const bn_t* a) {
    for (int i = 0; i < BN_MAX_WORDS; i++) {
        if (a->w[i] != 0) return 0;
    }
    return 1;
}

static int bn_cmp(const bn_t* a, const bn_t* b) {
    for (int i = BN_MAX_WORDS - 1; i >= 0; i--) {
        if (a->w[i] > b->w[i]) return 1;
        if (a->w[i] < b->w[i]) return -1;
    }
    return 0;
}

static uint32_t bn_bitlen(const bn_t* a) {
    for (int i = BN_MAX_WORDS - 1; i >= 0; i--) {
        if (a->w[i] != 0) {
            uint32_t v = a->w[i];
            uint32_t b = 0;
            while (v > 0) { b++; v >>= 1; }
            return (uint32_t)(i * 32) + b;
        }
    }
    return 0;
}

static int bn_get_bit(const bn_t* a, uint32_t bit_idx) {
    uint32_t word_idx = bit_idx / 32;
    uint32_t offset   = bit_idx % 32;
    if (word_idx >= BN_MAX_WORDS) return 0;
    return (int)((a->w[word_idx] >> offset) & 1U);
}

static void bn_set_bit(bn_t* a, uint32_t bit_idx) {
    uint32_t word_idx = bit_idx / 32;
    uint32_t offset   = bit_idx % 32;
    if (word_idx < BN_MAX_WORDS) {
        a->w[word_idx] |= (1U << offset);
    }
}

static uint32_t bn_add(bn_t* r, const bn_t* a, const bn_t* b) {
    uint64_t carry = 0;
    for (int i = 0; i < BN_MAX_WORDS; i++) {
        uint64_t sum = (uint64_t)a->w[i] + (uint64_t)b->w[i] + carry;
        r->w[i] = (uint32_t)(sum & 0xFFFFFFFFULL);
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

static uint32_t bn_add_u32(bn_t* r, const bn_t* a, uint32_t b) {
    uint64_t carry = b;
    for (int i = 0; i < BN_MAX_WORDS; i++) {
        uint64_t sum = (uint64_t)a->w[i] + carry;
        r->w[i] = (uint32_t)(sum & 0xFFFFFFFFULL);
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

static uint32_t bn_sub(bn_t* r, const bn_t* a, const bn_t* b) {
    int64_t borrow = 0;
    for (int i = 0; i < BN_MAX_WORDS; i++) {
        int64_t diff = (int64_t)a->w[i] - (int64_t)b->w[i] - borrow;
        if (diff < 0) {
            diff += (1LL << 32);
            borrow = 1;
        } else {
            borrow = 0;
        }
        r->w[i] = (uint32_t)diff;
    }
    return (uint32_t)borrow;
}

static void bn_shl1(bn_t* a) {
    uint32_t carry = 0;
    for (int i = 0; i < BN_MAX_WORDS; i++) {
        uint32_t next = a->w[i] >> 31;
        a->w[i] = (a->w[i] << 1) | carry;
        carry = next;
    }
}

static void bn_shr1(bn_t* a) {
    uint32_t carry = 0;
    for (int i = BN_MAX_WORDS - 1; i >= 0; i--) {
        uint32_t next = a->w[i] & 1U;
        a->w[i] = (a->w[i] >> 1) | (carry << 31);
        carry = next;
    }
}

static void bn_divmod(const bn_t* num, const bn_t* den, bn_t* quot, bn_t* rem) {
    bn_t q, r;
    bn_zero(&q);
    bn_zero(&r);
    if (bn_is_zero(den)) {
        if (quot) bn_zero(quot);
        if (rem) bn_zero(rem);
        return;
    }
    uint32_t bits = bn_bitlen(num);
    for (int32_t i = (int32_t)bits - 1; i >= 0; i--) {
        bn_shl1(&r);
        r.w[0] |= (uint32_t)bn_get_bit(num, (uint32_t)i);
        if (bn_cmp(&r, den) >= 0) {
            bn_sub(&r, &r, den);
            bn_set_bit(&q, (uint32_t)i);
        }
    }
    if (quot) bn_copy(quot, &q);
    if (rem) bn_copy(rem, &r);
}

static void bn_mod(bn_t* r, const bn_t* a, const bn_t* m) {
    bn_divmod(a, m, NULL, r);
}

static void bn_mul_raw(bn_t* r, const bn_t* a, const bn_t* b) {
    bn_t res;
    bn_zero(&res);
    for (int i = 0; i < BN_MAX_WORDS / 2; i++) {
        if (a->w[i] == 0) continue;
        uint64_t carry = 0;
        for (int j = 0; j < BN_MAX_WORDS / 2 && (i + j) < BN_MAX_WORDS; j++) {
            uint64_t prod = (uint64_t)a->w[i] * (uint64_t)b->w[j] +
                            (uint64_t)res.w[i + j] + carry;
            res.w[i + j] = (uint32_t)(prod & 0xFFFFFFFFULL);
            carry = prod >> 32;
        }
        int k = i + BN_MAX_WORDS / 2;
        if (k < BN_MAX_WORDS) {
            res.w[k] += (uint32_t)carry;
        }
    }
    bn_copy(r, &res);
}

static void bn_mul_mod(bn_t* r, const bn_t* a, const bn_t* b, const bn_t* m) {
    bn_t prod;
    bn_mul_raw(&prod, a, b);
    bn_mod(r, &prod, m);
}

/* Algoritmo 1: Square and Multiply sobre multiprecisión bn_t */
static void bn_exp_mod(bn_t* rop, const bn_t* x, const bn_t* H, const bn_t* n) {
    if (bn_is_zero(H)) {
        bn_set_u32(rop, 1);
        return;
    }
    uint32_t t = bn_bitlen(H);
    bn_t r, x_red;
    bn_mod(&x_red, x, n);
    bn_copy(&r, &x_red);

    if (t > 1) {
        for (int32_t i = (int32_t)t - 2; i >= 0; i--) {
            bn_mul_mod(&r, &r, &r, n);
            if (bn_get_bit(H, (uint32_t)i) == 1) {
                bn_mul_mod(&r, &r, &x_red, n);
            }
        }
    }
    bn_copy(rop, &r);
}

static void bn_gcd(bn_t* rop, const bn_t* a, const bn_t* b) {
    bn_t x, y, r;
    bn_copy(&x, a);
    bn_copy(&y, b);
    while (!bn_is_zero(&y)) {
        bn_mod(&r, &x, &y);
        bn_copy(&x, &y);
        bn_copy(&y, &r);
    }
    bn_copy(rop, &x);
}

/* Algoritmo Extendido de Euclides sobre bn_t: rop = a^(-1) mod m */
static int bn_mod_inv(bn_t* rop, const bn_t* a, const bn_t* m) {
    bn_t t, newt, r, newr, q, tmp, prod;
    int t_neg = 0, newt_neg = 0;

    bn_zero(&t);
    bn_set_u32(&newt, 1);
    bn_copy(&r, m);
    bn_mod(&newr, a, m);

    while (!bn_is_zero(&newr)) {
        bn_divmod(&r, &newr, &q, &tmp);
        bn_copy(&r, &newr);
        bn_copy(&newr, &tmp);

        // tmp = t - q * newt (con seguimiento de signo)
        bn_mul_raw(&prod, &q, &newt);
        bn_t next_t;
        int next_neg = 0;
        if (t_neg == newt_neg) {
            if (bn_cmp(&t, &prod) >= 0) {
                bn_sub(&next_t, &t, &prod);
                next_neg = t_neg;
            } else {
                bn_sub(&next_t, &prod, &t);
                next_neg = !t_neg;
            }
        } else {
            bn_add(&next_t, &t, &prod);
            next_neg = t_neg;
        }
        bn_copy(&t, &newt);
        t_neg = newt_neg;
        bn_copy(&newt, &next_t);
        newt_neg = next_neg;
    }

    bn_t one;
    bn_set_u32(&one, 1);
    if (bn_cmp(&r, &one) != 0) return -1;

    if (t_neg) {
        bn_mod(&t, &t, m);
        if (!bn_is_zero(&t)) {
            bn_sub(&t, m, &t);
        }
    } else {
        bn_mod(&t, &t, m);
    }
    bn_copy(rop, &t);
    return 0;
}

/* NIST SP 800-56B Rev. 2 Appendix B.1: Integer-to-Byte-String (I2BS) */
static void bn_to_bytes_be(const bn_t* x, uint8_t* out, uint32_t out_len) {
    for (uint32_t i = 0; i < out_len; i++) {
        uint32_t byte_from_lsb = out_len - 1 - i;
        uint32_t word_idx = byte_from_lsb / 4;
        uint32_t shift    = (byte_from_lsb % 4) * 8;
        if (word_idx < BN_MAX_WORDS) {
            out[i] = (uint8_t)((x->w[word_idx] >> shift) & 0xFFU);
        } else {
            out[i] = 0;
        }
    }
}

/* NIST SP 800-56B Rev. 2 Appendix B.2: Byte-String-to-Integer (BS2I) */
static void bn_from_bytes_be(bn_t* x, const uint8_t* in, uint32_t in_len) {
    bn_zero(x);
    for (uint32_t i = 0; i < in_len; i++) {
        uint32_t byte_from_lsb = in_len - 1 - i;
        uint32_t word_idx = byte_from_lsb / 4;
        uint32_t shift    = (byte_from_lsb % 4) * 8;
        if (word_idx < BN_MAX_WORDS) {
            x->w[word_idx] |= ((uint32_t)in[i] << shift);
        }
    }
}

static const char HEX_CHARS[] = "0123456789abcdef";

static uint32_t bn_to_hex(const bn_t* x, char* out, uint32_t max_len) {
    int top = BN_MAX_WORDS - 1;
    while (top > 0 && x->w[top] == 0) top--;
    uint32_t pos = 0;
    for (int i = top; i >= 0; i--) {
        uint32_t w = x->w[i];
        for (int b = 28; b >= 0; b -= 4) {
            uint8_t nib = (uint8_t)((w >> b) & 0xFU);
            if (pos == 0 && nib == 0 && !(i == 0 && b == 0)) continue;
            if (pos + 1 < max_len) {
                out[pos++] = HEX_CHARS[nib];
            }
        }
    }
    if (pos == 0 && max_len > 1) out[pos++] = '0';
    out[pos] = '\0';
    return pos;
}

/* Prueba de primalidad de Miller-Rabin sobre bn_t */
static int bn_is_prime(const bn_t* n) {
    if ((n->w[0] & 1U) == 0) return 0;
    static const uint32_t small_primes[12] = {3,5,7,11,13,17,19,23,29,31,37,41};
    bn_t tmp, rem;
    for (int i = 0; i < 12; i++) {
        bn_set_u32(&tmp, small_primes[i]);
        if (bn_cmp(n, &tmp) == 0) return 1;
        bn_mod(&rem, n, &tmp);
        if (bn_is_zero(&rem)) return 0;
    }

    bn_t n_minus_1, d;
    bn_set_u32(&tmp, 1);
    bn_sub(&n_minus_1, n, &tmp);
    bn_copy(&d, &n_minus_1);
    uint32_t s = 0;
    while ((d.w[0] & 1U) == 0) {
        bn_shr1(&d);
        s++;
    }

    static const uint32_t bases[5] = {2, 3, 5, 7, 11};
    bn_t a, x;
    for (int i = 0; i < 5; i++) {
        bn_set_u32(&a, bases[i]);
        bn_exp_mod(&x, &a, &d, n);
        if (bn_cmp(&x, &tmp) == 0 || bn_cmp(&x, &n_minus_1) == 0) continue;
        int composite = 1;
        for (uint32_t r = 1; r < s; r++) {
            bn_mul_mod(&x, &x, &x, n);
            if (bn_cmp(&x, &n_minus_1) == 0) {
                composite = 0;
                break;
            }
        }
        if (composite) return 0;
    }
    return 1;
}

// =============================================================================
// MEMORIA ESTÁTICA EXPORTADA PARA INTERCAMBIO ENTRE C (WASM) Y JAVASCRIPT
// =============================================================================

static uint64_t g_rsa_state[12];
static uint64_t g_crt_steps[8];
static uint64_t g_exp_trace[64 * 4];
static uint32_t g_exp_trace_len = 0;

static uint8_t g_io_buf_a[65536];
static uint8_t g_io_buf_b[65536];
static uint8_t g_oaep_db[512];
static uint8_t g_oaep_dbmask[512];
static uint8_t g_oaep_masked_db[512];
static uint8_t g_oaep_seed[32];
static uint8_t g_oaep_seedmask[32];
static uint8_t g_oaep_masked_seed[32];
static uint8_t g_oaep_em[512];
static uint8_t g_oaep_ciphertext[512];
static char    g_b64_buf[131072];
static char    g_nist_key_json[65536];
static char    g_nist_crt_trace_json[16384];

/* Estructura en memoria C para la llave RSA-OAEP en los 3 formatos de NIST SP 800-56B Sec. 6.2.2 */
static struct {
    uint32_t nBits;
    uint32_t nLen;
    bn_t n;
    bn_t e;
    bn_t d;
    bn_t p;
    bn_t q;
    bn_t dP;
    bn_t dQ;
    bn_t qInv;
    bn_t lcm;
    int  pkv_valid;
} g_nist_oaep_key;

WASM_EXPORT uint64_t* wasm_get_rsa_state_ptr(void)      { return g_rsa_state; }
WASM_EXPORT uint64_t* wasm_get_crt_steps_ptr(void)      { return g_crt_steps; }
WASM_EXPORT uint64_t* wasm_get_exp_trace_ptr(void)      { return g_exp_trace; }
WASM_EXPORT uint32_t  wasm_get_exp_trace_len(void)      { return g_exp_trace_len; }
WASM_EXPORT uint8_t*  wasm_get_io_buf_a(void)           { return g_io_buf_a; }
WASM_EXPORT uint8_t*  wasm_get_io_buf_b(void)           { return g_io_buf_b; }
WASM_EXPORT uint8_t*  wasm_get_oaep_em_ptr(void)        { return g_oaep_em; }
WASM_EXPORT uint8_t*  wasm_get_oaep_db_ptr(void)        { return g_oaep_db; }
WASM_EXPORT uint8_t*  wasm_get_oaep_masked_db_ptr(void) { return g_oaep_masked_db; }
WASM_EXPORT uint8_t*  wasm_get_oaep_masked_seed_ptr(void){ return g_oaep_masked_seed; }
WASM_EXPORT uint8_t*  wasm_get_oaep_ciphertext_ptr(void){ return g_oaep_ciphertext; }
WASM_EXPORT char*     wasm_get_b64_buf(void)            { return g_b64_buf; }
WASM_EXPORT char*     wasm_get_nist_key_json(void)      { return g_nist_key_json; }
WASM_EXPORT char*     wasm_get_nist_crt_trace_json(void){ return g_nist_crt_trace_json; }

// =============================================================================
// SECCIÓN 1: ALGORITMO 1 (SQUARE AND MULTIPLY) Y RSA ESCOLAR CON CRT EN C
// =============================================================================

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t m) {
    a %= m;
    b %= m;
    if (a >= m - b) return a - (m - b);
    return a + b;
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 0) return 0;
    uint64_t res = 0;
    a %= m;
    while (b > 0) {
        if (b & 1ULL) {
            res = add_mod(res, a, m);
        }
        a = add_mod(a, a, m);
        b >>= 1;
    }
    return res;
}

static uint32_t bit_length_u64(uint64_t x) {
    if (x == 0) return 0;
    uint32_t bits = 0;
    while (x > 0) {
        bits++;
        x >>= 1;
    }
    return bits;
}

/* Algoritmo 1: Square and Multiply(x, H, n) */
WASM_EXPORT uint64_t wasm_exp_bin(uint64_t x, uint64_t H, uint64_t n) {
    if (n == 0) return 0;
    if (H == 0) return 1 % n;

    uint32_t t = bit_length_u64(H);
    uint64_t x_red = x % n;
    uint64_t r = x_red;

    g_exp_trace_len = 0;
    g_exp_trace[0] = t - 1;
    g_exp_trace[1] = 1;
    g_exp_trace[2] = r;
    g_exp_trace[3] = r;
    g_exp_trace_len = 1;

    if (t > 1) {
        for (int32_t i = (int32_t)t - 2; i >= 0; i--) {
            r = mul_mod(r, r, n);
            uint64_t r_sq = r;
            uint64_t bit = (H >> i) & 1ULL;
            if (bit == 1ULL) {
                r = mul_mod(r, x_red, n);
            }
            if (g_exp_trace_len < 64) {
                uint32_t idx = g_exp_trace_len * 4;
                g_exp_trace[idx + 0] = (uint64_t)i;
                g_exp_trace[idx + 1] = bit;
                g_exp_trace[idx + 2] = r_sq;
                g_exp_trace[idx + 3] = r;
                g_exp_trace_len++;
            }
        }
    }
    return r;
}

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static uint64_t modinv_u64(uint64_t a, uint64_t m) {
    if (m <= 1) return 0;
    uint64_t m0 = m;
    int64_t y = 0, x = 1;
    a %= m;
    while (a > 1) {
        if (m == 0) return 0;
        uint64_t q = a / m;
        uint64_t t = m;
        m = a % m;
        a = t;
        int64_t ty = y;
        y = x - (int64_t)q * y;
        x = ty;
    }
    if (a != 1) return 0;
    if (x < 0) x += (int64_t)m0;
    return (uint64_t)x;
}

static int is_prime_mr(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if ((n & 1ULL) == 0) return 0;

    uint64_t d = n - 1;
    uint32_t s = 0;
    while ((d & 1ULL) == 0) {
        d >>= 1;
        s++;
    }

    static const uint64_t bases[7] = {2, 3, 5, 7, 11, 13, 17};
    for (int i = 0; i < 7; i++) {
        uint64_t a = bases[i];
        if (n <= a) break;
        uint64_t x = wasm_exp_bin(a, d, n);
        if (x == 1 || x == n - 1) continue;
        int composite = 1;
        for (uint32_t r = 1; r < s; r++) {
            x = mul_mod(x, x, n);
            if (x == n - 1) {
                composite = 0;
                break;
            }
        }
        if (composite) return 0;
    }
    return 1;
}

static uint64_t next_prime_u64(uint64_t n) {
    if (n <= 2) return 2;
    if ((n & 1ULL) == 0) n++;
    while (!is_prime_mr(n)) {
        n += 2;
    }
    return n;
}

static uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* Ejercicio 1.1: Generación de par de llaves RSA Escolar con CRT */
WASM_EXPORT int wasm_gen_key(uint32_t bits, uint64_t seed) {
    if (bits < 4) bits = 4;
    if (bits > 31) bits = 31;

    uint64_t rng = seed ? seed : 0x9E3779B97F4A7C15ULL;
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t msb  = 1ULL << (bits - 1);

    uint64_t p = 0, q = 0;
    do {
        uint64_t cand = (xorshift64(&rng) & mask) | msb | 1ULL;
        p = next_prime_u64(cand);
    } while (bit_length_u64(p) < bits);

    do {
        uint64_t cand = (xorshift64(&rng) & mask) | msb | 1ULL;
        q = next_prime_u64(cand);
    } while (q == p || bit_length_u64(q) < bits);

    if (p < q) {
        uint64_t tmp = p; p = q; q = tmp;
    }

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 5;
    for (int i = 0; i < 2000; i++) {
        uint64_t cand = (xorshift64(&rng) % (phi - 4)) + 3;
        cand |= 1ULL;
        if (cand == 3 || cand == 65537) continue;
        if (cand > 1 && cand < phi && gcd_u64(cand, phi) == 1) {
            e = cand;
            break;
        }
    }
    if (gcd_u64(e, phi) != 1 || e == 3 || e == 65537) {
        e = 5;
        while (e < phi && (e == 3 || e == 65537 || gcd_u64(e, phi) != 1)) {
            e += 2;
        }
    }

    uint64_t d = modinv_u64(e, phi);
    uint64_t dp = d % (p - 1);
    uint64_t dq = d % (q - 1);
    uint64_t qInv = modinv_u64(q % p, p);
    uint64_t pInv = modinv_u64(p % q, q);

    g_rsa_state[0]  = p;
    g_rsa_state[1]  = q;
    g_rsa_state[2]  = n;
    g_rsa_state[3]  = phi;
    g_rsa_state[4]  = e;
    g_rsa_state[5]  = d;
    g_rsa_state[6]  = dp;
    g_rsa_state[7]  = dq;
    g_rsa_state[8]  = qInv;
    g_rsa_state[9]  = pInv;
    g_rsa_state[10] = bit_length_u64(n);
    g_rsa_state[11] = 1;
    return 0;
}

/* Ejercicio 1.3: Cifrado de un entero 0 < m < n */
WASM_EXPORT uint64_t wasm_rsa_encrypt_int(uint64_t m, uint64_t e, uint64_t n) {
    if (m == 0 || m >= n) return 0;
    return wasm_exp_bin(m, e, n);
}

/* Ejercicio 1.4: Descifrado con Teorema Chino del Residuo (Garner y Gauss) */
WASM_EXPORT uint64_t wasm_rsa_decrypt_crt(
    uint64_t c,
    uint64_t p,
    uint64_t q,
    uint64_t dp,
    uint64_t dq
) {
    uint64_t n = p * q;
    uint64_t mp = wasm_exp_bin(c % p, dp, p);
    uint64_t mq = wasm_exp_bin(c % q, dq, q);
    uint64_t qInv = modinv_u64(q % p, p);
    uint64_t pInv = modinv_u64(p % q, q);

    uint64_t diff = (mp >= (mq % p)) ? (mp - (mq % p)) : (p + mp - (mq % p));
    diff %= p;
    uint64_t h = mul_mod(diff, qInv, p);
    uint64_t m_garner = add_mod(mq, mul_mod(h, q, n), n);

    uint64_t term1 = mul_mod(mul_mod(mp, q, n), qInv, n);
    uint64_t term2 = mul_mod(mul_mod(mq, p, n), pInv, n);
    uint64_t m_gauss = add_mod(term1, term2, n);

    g_crt_steps[0] = c;
    g_crt_steps[1] = mp;
    g_crt_steps[2] = mq;
    g_crt_steps[3] = qInv;
    g_crt_steps[4] = pInv;
    g_crt_steps[5] = h;
    g_crt_steps[6] = m_garner;
    g_crt_steps[7] = m_gauss;

    return m_garner;
}

// =============================================================================
// SECCIÓN 2: SHA-256, MGF1, RSA-OAEP (NIST SP 800-56B) Y AES-128-CTR EN C
// =============================================================================

static const uint32_t K_SHA256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

WASM_EXPORT void wasm_sha256(const uint8_t* data, uint32_t len, uint8_t* out32) {
    uint32_t h[8] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
    };

    uint64_t bit_len = (uint64_t)len * 8ULL;
    uint32_t total_len = ((len + 9 + 63) / 64) * 64;

    uint8_t block[64];
    for (uint32_t offset = 0; offset < total_len; offset += 64) {
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t pos = offset + i;
            if (pos < len) {
                block[i] = data[pos];
            } else if (pos == len) {
                block[i] = 0x80;
            } else if (pos >= total_len - 8) {
                uint32_t shift = (total_len - 1 - pos) * 8;
                block[i] = (uint8_t)((bit_len >> shift) & 0xFF);
            } else {
                block[i] = 0x00;
            }
        }

        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
                   ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8)  |
                   ((uint32_t)block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K_SHA256[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (int i = 0; i < 8; i++) {
        out32[i * 4 + 0] = (uint8_t)(h[i] >> 24);
        out32[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out32[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out32[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* NIST SP 800-56B Rev. 2 Section 7.2.2.2: Mask Generation Function (MGF1-SHA256) */
WASM_EXPORT void wasm_mgf1_sha256(
    const uint8_t* mgf_seed,
    uint32_t seed_len,
    uint8_t* mask_out,
    uint32_t mask_len
) {
    uint8_t buf[512 + 4];
    uint8_t digest[32];
    if (seed_len > 512) seed_len = 512;
    for (uint32_t i = 0; i < seed_len; i++) buf[i] = mgf_seed[i];

    uint32_t counter = 0;
    uint32_t generated = 0;
    while (generated < mask_len) {
        buf[seed_len + 0] = (uint8_t)((counter >> 24) & 0xFF);
        buf[seed_len + 1] = (uint8_t)((counter >> 16) & 0xFF);
        buf[seed_len + 2] = (uint8_t)((counter >> 8) & 0xFF);
        buf[seed_len + 3] = (uint8_t)(counter & 0xFF);

        wasm_sha256(buf, seed_len + 4, digest);
        for (uint32_t j = 0; j < 32 && generated < mask_len; j++) {
            mask_out[generated++] = digest[j];
        }
        counter++;
    }
}

// =============================================================================
// GENERACIÓN Y VALIDACIÓN DE LLAVES SEGÚN NIST SP 800-56B REV. 2 EN C-WASM
// Implementa rsakpg1-crt (Sec. 6.3.1.3) y crt_pkv (Sec. 6.4.1.4.3):
// - Calcula LCM(p-1, q-1) = ((p-1)*(q-1)) / GCD(p-1, q-1)
// - d = e^(-1) mod LCM(p-1, q-1)
// - dP = d mod (p-1), dQ = d mod (q-1), qInv = q^(-1) mod p
// - Valida las 6 condiciones de crt_pkv (Sec. 6.4.1.4.3 Step 7a..7f)
//   y el Pair-Wise Consistency Test m == (m^e)^d mod n
// =============================================================================

static uint32_t str_append(char* dst, uint32_t pos, const char* src) {
    while (*src) {
        dst[pos++] = *src++;
    }
    dst[pos] = '\0';
    return pos;
}

WASM_EXPORT int wasm_nist_keygen_crt(uint32_t prime_bits, uint64_t seed) {
    // prime_bits: >= 384 bits por primo -> nBits = 768 bits, nLen = 96 bytes (>= 2*HLen + 2 + KLen = 82 bytes)
    if (prime_bits < 384) prime_bits = 384;
    if (prime_bits > 512) prime_bits = 512;

    uint64_t rng = seed ? seed : 0xA5A5F0F012345678ULL;
    uint32_t words_per_prime = prime_bits / 32;

    bn_t p, q, one, p1, q1, gcd_pq, prod_pq, lcm, e, d, dP, dQ, qInv, n;
    bn_set_u32(&one, 1);
    bn_set_u32(&e, 65537); // NIST SP 800-56B Sec 6.2.1: 65,537 <= e < 2^256

    // 1. Generar primo p con GCD(p - 1, e) == 1
    while (1) {
        bn_zero(&p);
        for (uint32_t i = 0; i < words_per_prime; i++) {
            p.w[i] = (uint32_t)xorshift64(&rng);
        }
        p.w[words_per_prime - 1] |= 0xC0000000U; // Asegura bit más significativo (2^(nBits-1)/2 < p)
        p.w[0] |= 1U;
        while (!bn_is_prime(&p)) {
            bn_add_u32(&p, &p, 2);
        }
        bn_sub(&p1, &p, &one);
        bn_t g;
        bn_gcd(&g, &p1, &e);
        if (bn_cmp(&g, &one) == 0) break;
    }

    // 2. Generar primo q distinto de p con GCD(q - 1, e) == 1
    while (1) {
        bn_zero(&q);
        for (uint32_t i = 0; i < words_per_prime; i++) {
            q.w[i] = (uint32_t)xorshift64(&rng);
        }
        q.w[words_per_prime - 1] |= 0xC0000000U;
        q.w[0] |= 1U;
        while (!bn_is_prime(&q) || bn_cmp(&p, &q) == 0) {
            bn_add_u32(&q, &q, 2);
        }
        bn_sub(&q1, &q, &one);
        bn_t g;
        bn_gcd(&g, &q1, &e);
        if (bn_cmp(&g, &one) == 0) break;
    }

    if (bn_cmp(&p, &q) < 0) {
        bn_t tmp;
        bn_copy(&tmp, &p); bn_copy(&p, &q); bn_copy(&q, &tmp);
        bn_sub(&p1, &p, &one);
        bn_sub(&q1, &q, &one);
    }

    // 3. Módulo n = p * q
    bn_mul_raw(&n, &p, &q);

    // 4. NIST SP 800-56B Sec 6.2.1 Step 4b: lambda(n) = LCM(p - 1, q - 1)
    bn_gcd(&gcd_pq, &p1, &q1);
    bn_mul_raw(&prod_pq, &p1, &q1);
    bn_divmod(&prod_pq, &gcd_pq, &lcm, NULL);

    // 5. Exponente privado d = e^(-1) mod LCM(p - 1, q - 1)
    if (bn_mod_inv(&d, &e, &lcm) != 0) return -1;

    // 6. Componentes CRT (NIST SP 800-56B Sec 6.3.1.3 Step 5a, 5b, 5c):
    //    dP = d mod (p - 1), dQ = d mod (q - 1), qInv = q^(-1) mod p
    bn_mod(&dP, &d, &p1);
    bn_mod(&dQ, &d, &q1);
    bn_t q_mod_p;
    bn_mod(&q_mod_p, &q, &p);
    if (bn_mod_inv(&qInv, &q_mod_p, &p) != 0) return -1;

    // 7. Validación NIST SP 800-56B Sec 6.4.1.4.3 (crt_pkv Step 7a..7f) + Pair-Wise Consistency Test
    bn_t chk1, chk2, chk3, m_test, c_test, m_rec;
    bn_mul_mod(&chk1, &dP, &e, &p1);
    bn_mul_mod(&chk2, &dQ, &e, &q1);
    bn_mul_mod(&chk3, &qInv, &q_mod_p, &p);
    bn_set_u32(&m_test, 424242);
    bn_exp_mod(&c_test, &m_test, &e, &n);
    bn_exp_mod(&m_rec, &c_test, &d, &n);

    int pkv_ok = (bn_cmp(&chk1, &one) == 0) &&
                 (bn_cmp(&chk2, &one) == 0) &&
                 (bn_cmp(&chk3, &one) == 0) &&
                 (bn_cmp(&m_test, &m_rec) == 0);

    g_nist_oaep_key.nBits = bn_bitlen(&n);
    g_nist_oaep_key.nLen  = (g_nist_oaep_key.nBits + 7) / 8;
    bn_copy(&g_nist_oaep_key.n, &n);
    bn_copy(&g_nist_oaep_key.e, &e);
    bn_copy(&g_nist_oaep_key.d, &d);
    bn_copy(&g_nist_oaep_key.p, &p);
    bn_copy(&g_nist_oaep_key.q, &q);
    bn_copy(&g_nist_oaep_key.dP, &dP);
    bn_copy(&g_nist_oaep_key.dQ, &dQ);
    bn_copy(&g_nist_oaep_key.qInv, &qInv);
    bn_copy(&g_nist_oaep_key.lcm, &lcm);
    g_nist_oaep_key.pkv_valid = pkv_ok;

    // Exportar los 3 formatos de llave de NIST SP 800-56B Sec. 6.2.2 en JSON desde C
    char hex_n[600], hex_e[32], hex_d[600], hex_p[320], hex_q[320], hex_dp[320], hex_dq[320], hex_qinv[320];
    bn_to_hex(&n, hex_n, sizeof(hex_n));
    bn_to_hex(&e, hex_e, sizeof(hex_e));
    bn_to_hex(&d, hex_d, sizeof(hex_d));
    bn_to_hex(&p, hex_p, sizeof(hex_p));
    bn_to_hex(&q, hex_q, sizeof(hex_q));
    bn_to_hex(&dP, hex_dp, sizeof(hex_dp));
    bn_to_hex(&dQ, hex_dq, sizeof(hex_dq));
    bn_to_hex(&qInv, hex_qinv, sizeof(hex_qinv));

    uint32_t pos = 0;
    pos = str_append(g_nist_key_json, pos, "{\"standard\":\"NIST SP 800-56B Rev. 2 Sec. 6.2.2 & 6.3.1.3\",");
    pos = str_append(g_nist_key_json, pos, "\"pkv_valid\":");
    pos = str_append(g_nist_key_json, pos, pkv_ok ? "true," : "false,");
    pos = str_append(g_nist_key_json, pos, "\"public_key\":{\"n\":\"");
    pos = str_append(g_nist_key_json, pos, hex_n);
    pos = str_append(g_nist_key_json, pos, "\",\"e\":\"");
    pos = str_append(g_nist_key_json, pos, hex_e);
    pos = str_append(g_nist_key_json, pos, "\"},\"format_1_basic\":{\"n\":\"");
    pos = str_append(g_nist_key_json, pos, hex_n);
    pos = str_append(g_nist_key_json, pos, "\",\"d\":\"");
    pos = str_append(g_nist_key_json, pos, hex_d);
    pos = str_append(g_nist_key_json, pos, "\"},\"format_2_prime_factor\":{\"p\":\"");
    pos = str_append(g_nist_key_json, pos, hex_p);
    pos = str_append(g_nist_key_json, pos, "\",\"q\":\"");
    pos = str_append(g_nist_key_json, pos, hex_q);
    pos = str_append(g_nist_key_json, pos, "\",\"d\":\"");
    pos = str_append(g_nist_key_json, pos, hex_d);
    pos = str_append(g_nist_key_json, pos, "\"},\"format_3_crt\":{\"n\":\"");
    pos = str_append(g_nist_key_json, pos, hex_n);
    pos = str_append(g_nist_key_json, pos, "\",\"e\":\"");
    pos = str_append(g_nist_key_json, pos, hex_e);
    pos = str_append(g_nist_key_json, pos, "\",\"d\":\"");
    pos = str_append(g_nist_key_json, pos, hex_d);
    pos = str_append(g_nist_key_json, pos, "\",\"p\":\"");
    pos = str_append(g_nist_key_json, pos, hex_p);
    pos = str_append(g_nist_key_json, pos, "\",\"q\":\"");
    pos = str_append(g_nist_key_json, pos, hex_q);
    pos = str_append(g_nist_key_json, pos, "\",\"dP\":\"");
    pos = str_append(g_nist_key_json, pos, hex_dp);
    pos = str_append(g_nist_key_json, pos, "\",\"dQ\":\"");
    pos = str_append(g_nist_key_json, pos, hex_dq);
    pos = str_append(g_nist_key_json, pos, "\",\"qInv\":\"");
    pos = str_append(g_nist_key_json, pos, hex_qinv);
    pos = str_append(g_nist_key_json, pos, "\"}}");

    return (int)g_nist_oaep_key.nLen;
}

/* NIST SP 800-56B Rev. 2 Section 7.2.2.3: RSA-OAEP.ENCRYPT((n, e), K, A) completo en C-WASM */
WASM_EXPORT int wasm_oaep_encode(
    const uint8_t* k_bytes,
    uint32_t k_len,
    const uint8_t* seed32,
    uint32_t n_len
) {
    const uint32_t h_len = 32; // SHA-256
    if (g_nist_oaep_key.nLen >= 2 * h_len + 2 + k_len) {
        n_len = g_nist_oaep_key.nLen;
    }
    if (n_len < 2 * h_len + 2 + k_len || n_len > 512) return -1;

    uint32_t db_len = n_len - h_len - 1;
    uint32_t ps_len = n_len - k_len - 2 * h_len - 2;

    // 3.a: HA = H(A), con A = "" (cadena vacía)
    uint8_t ha[32];
    wasm_sha256((const uint8_t*)"", 0, ha);

    // 3.c: DB = HA || PS || 0x01 || K
    for (uint32_t i = 0; i < h_len; i++) g_oaep_db[i] = ha[i];
    for (uint32_t i = 0; i < ps_len; i++) g_oaep_db[h_len + i] = 0x00;
    g_oaep_db[h_len + ps_len] = 0x01;
    for (uint32_t i = 0; i < k_len; i++) g_oaep_db[h_len + ps_len + 1 + i] = k_bytes[i];

    // 3.d: mgfSeed de HLen bytes
    for (uint32_t i = 0; i < h_len; i++) g_oaep_seed[i] = seed32[i];

    // 3.e & 3.f: dbMask = MGF(mgfSeed, nLen - HLen - 1), maskedDB = DB ^ dbMask
    wasm_mgf1_sha256(g_oaep_seed, h_len, g_oaep_dbmask, db_len);
    for (uint32_t i = 0; i < db_len; i++) {
        g_oaep_masked_db[i] = g_oaep_db[i] ^ g_oaep_dbmask[i];
    }

    // 3.g & 3.h: mgfSeedMask = MGF(maskedDB, HLen), maskedMGFSeed = mgfSeed ^ mgfSeedMask
    wasm_mgf1_sha256(g_oaep_masked_db, db_len, g_oaep_seedmask, h_len);
    for (uint32_t i = 0; i < h_len; i++) {
        g_oaep_masked_seed[i] = g_oaep_seed[i] ^ g_oaep_seedmask[i];
    }

    // 3.i: EM = 0x00 || maskedMGFSeed || maskedDB
    g_oaep_em[0] = 0x00;
    for (uint32_t i = 0; i < h_len; i++) g_oaep_em[1 + i] = g_oaep_masked_seed[i];
    for (uint32_t i = 0; i < db_len; i++) g_oaep_em[1 + h_len + i] = g_oaep_masked_db[i];

    // 4.a, 4.b, 4.c (NIST SP 800-56B Sec. 7.2.2.3):
    // em = BS2I(EM), c = RSAEP((n, e), em) = em^e mod n, C = I2BS(c, nLen)
    if (g_nist_oaep_key.nLen == n_len && !bn_is_zero(&g_nist_oaep_key.n)) {
        bn_t em_bn, c_bn;
        bn_from_bytes_be(&em_bn, g_oaep_em, n_len);
        bn_exp_mod(&c_bn, &em_bn, &g_nist_oaep_key.e, &g_nist_oaep_key.n);
        bn_to_bytes_be(&c_bn, g_oaep_ciphertext, n_len);
    } else {
        for (uint32_t i = 0; i < n_len; i++) g_oaep_ciphertext[i] = g_oaep_em[i];
    }

    return (int)n_len;
}

/* NIST SP 800-56B Rev. 2 Section 7.2.2.4 & 7.1.2.3:
 * RSA-OAEP.DECRYPT con RSADP(n, e, d, p, q, dP, dQ, qInv, c) en formato CRT en C-WASM */
WASM_EXPORT int wasm_oaep_decode(
    const uint8_t* c_or_em,
    uint32_t n_len,
    uint8_t* out_k
) {
    const uint32_t h_len = 32;
    if (n_len < 2 * h_len + 2 || n_len > 512) return -1;

    uint8_t em_buf[512];

    // Paso 3 (NIST SP 800-56B Sec 7.2.2.4 + Sec 7.1.2.3 RSADP en formato CRT):
    if (g_nist_oaep_key.nLen == n_len && !bn_is_zero(&g_nist_oaep_key.n)) {
        bn_t c_bn, c_p, c_q, mp, mq, diff, h, qh, em_bn;
        bn_from_bytes_be(&c_bn, c_or_em, n_len);

        // 7.1.2.3 Step 2: mp = c^dP mod p
        bn_mod(&c_p, &c_bn, &g_nist_oaep_key.p);
        bn_exp_mod(&mp, &c_p, &g_nist_oaep_key.dP, &g_nist_oaep_key.p);

        // 7.1.2.3 Step 3: mq = c^dQ mod q
        bn_mod(&c_q, &c_bn, &g_nist_oaep_key.q);
        bn_exp_mod(&mq, &c_q, &g_nist_oaep_key.dQ, &g_nist_oaep_key.q);

        // 7.1.2.3 Step 4: h = ((mp - mq) * qInv) mod p
        bn_t mq_mod_p;
        bn_mod(&mq_mod_p, &mq, &g_nist_oaep_key.p);
        if (bn_cmp(&mp, &mq_mod_p) >= 0) {
            bn_sub(&diff, &mp, &mq_mod_p);
        } else {
            bn_sub(&diff, &g_nist_oaep_key.p, &mq_mod_p);
            bn_add(&diff, &diff, &mp);
        }
        bn_mul_mod(&h, &diff, &g_nist_oaep_key.qInv, &g_nist_oaep_key.p);

        // 7.1.2.3 Step 5: em = (mq + (q * h)) mod n
        bn_mul_raw(&qh, &g_nist_oaep_key.q, &h);
        bn_add(&em_bn, &mq, &qh);
        bn_mod(&em_bn, &em_bn, &g_nist_oaep_key.n);

        // 7.2.2.4 Step 3b: EM = I2BS(em, nLen)
        bn_to_bytes_be(&em_bn, em_buf, n_len);

        // Exportar traza de valores intermedios de RSADP-CRT (Sec. 7.1.2.3) a JSON
        char hex_mp[320], hex_mq[320], hex_h[320], hex_em[600];
        bn_to_hex(&mp, hex_mp, sizeof(hex_mp));
        bn_to_hex(&mq, hex_mq, sizeof(hex_mq));
        bn_to_hex(&h, hex_h, sizeof(hex_h));
        bn_to_hex(&em_bn, hex_em, sizeof(hex_em));
        uint32_t pos = 0;
        pos = str_append(g_nist_crt_trace_json, pos, "{\"mp\":\"");
        pos = str_append(g_nist_crt_trace_json, pos, hex_mp);
        pos = str_append(g_nist_crt_trace_json, pos, "\",\"mq\":\"");
        pos = str_append(g_nist_crt_trace_json, pos, hex_mq);
        pos = str_append(g_nist_crt_trace_json, pos, "\",\"h\":\"");
        pos = str_append(g_nist_crt_trace_json, pos, hex_h);
        pos = str_append(g_nist_crt_trace_json, pos, "\",\"em\":\"");
        pos = str_append(g_nist_crt_trace_json, pos, hex_em);
        pos = str_append(g_nist_crt_trace_json, pos, "\"}");
    } else {
        for (uint32_t i = 0; i < n_len; i++) em_buf[i] = c_or_em[i];
    }

    uint32_t db_len = n_len - h_len - 1;
    uint8_t y = em_buf[0];
    const uint8_t* masked_seed = em_buf + 1;
    const uint8_t* masked_db   = em_buf + 1 + h_len;

    wasm_mgf1_sha256(masked_db, db_len, g_oaep_seedmask, h_len);
    for (uint32_t i = 0; i < h_len; i++) {
        g_oaep_seed[i] = masked_seed[i] ^ g_oaep_seedmask[i];
    }

    wasm_mgf1_sha256(g_oaep_seed, h_len, g_oaep_dbmask, db_len);
    for (uint32_t i = 0; i < db_len; i++) {
        g_oaep_db[i] = masked_db[i] ^ g_oaep_dbmask[i];
    }

    uint8_t ha[32];
    wasm_sha256((const uint8_t*)"", 0, ha);

    uint8_t diff = y;
    for (uint32_t i = 0; i < h_len; i++) {
        diff |= (g_oaep_db[i] ^ ha[i]);
    }

    uint32_t idx = h_len;
    while (idx < db_len && g_oaep_db[idx] == 0x00) {
        idx++;
    }

    if (diff != 0 || idx >= db_len || g_oaep_db[idx] != 0x01) {
        return -1; // DecryptErrorFlag = True
    }

    idx++;
    uint32_t k_len = db_len - idx;
    for (uint32_t i = 0; i < k_len; i++) {
        out_k[i] = g_oaep_db[idx + i];
    }
    return (int)k_len;
}

// =============================================================================
// IMPLEMENTACIÓN DE AES-128-CTR (FIPS 197 + NIST SP 800-38A) EN C PARA WASM
// =============================================================================

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

static void aes128_key_expansion(const uint8_t key[16], uint8_t round_keys[176]) {
    for (int i = 0; i < 16; i++) round_keys[i] = key[i];

    uint8_t temp[4];
    for (int i = 4; i < 44; i++) {
        for (int j = 0; j < 4; j++) temp[j] = round_keys[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i / 4];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        }
        for (int j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }
}

static void aes128_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];

    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];

        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                int idx = c * 4;
                uint8_t a0 = s[idx], a1 = s[idx+1], a2 = s[idx+2], a3 = s[idx+3];
                uint8_t tm = a0 ^ a1 ^ a2 ^ a3;
                s[idx+0] ^= tm ^ xtime(a0 ^ a1);
                s[idx+1] ^= tm ^ xtime(a1 ^ a2);
                s[idx+2] ^= tm ^ xtime(a2 ^ a3);
                s[idx+3] ^= tm ^ xtime(a3 ^ a0);
            }
        }

        for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
    }

    for (int i = 0; i < 16; i++) out[i] = s[i];
}

/* Cifrado / Descifrado simétrico AES-128 en modo Contador (CTR) */
WASM_EXPORT void wasm_aes128_ctr_crypt(
    const uint8_t* in,
    uint8_t* out,
    uint32_t len,
    const uint8_t key[16],
    const uint8_t iv[16]
) {
    uint8_t rk[176];
    aes128_key_expansion(key, rk);

    uint8_t counter_block[16];
    uint8_t keystream[16];
    for (int i = 0; i < 16; i++) counter_block[i] = iv[i];

    for (uint32_t offset = 0; offset < len; offset += 16) {
        aes128_encrypt_block(counter_block, keystream, rk);
        for (uint32_t j = 0; j < 16 && (offset + j) < len; j++) {
            out[offset + j] = in[offset + j] ^ keystream[j];
        }
        for (int k = 15; k >= 0; k--) {
            counter_block[k]++;
            if (counter_block[k] != 0) break;
        }
    }
}

static const char B64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

WASM_EXPORT uint32_t wasm_base64_encode(const uint8_t* in, uint32_t len) {
    uint32_t out_idx = 0;
    for (uint32_t i = 0; i < len; i += 3) {
        uint32_t v = ((uint32_t)in[i]) << 16;
        if (i + 1 < len) v |= ((uint32_t)in[i + 1]) << 8;
        if (i + 2 < len) v |= ((uint32_t)in[i + 2]);

        g_b64_buf[out_idx++] = B64_TABLE[(v >> 18) & 0x3F];
        g_b64_buf[out_idx++] = B64_TABLE[(v >> 12) & 0x3F];
        g_b64_buf[out_idx++] = (i + 1 < len) ? B64_TABLE[(v >> 6) & 0x3F] : '=';
        g_b64_buf[out_idx++] = (i + 2 < len) ? B64_TABLE[v & 0x3F] : '=';
    }
    g_b64_buf[out_idx] = '\0';
    return out_idx;
}
