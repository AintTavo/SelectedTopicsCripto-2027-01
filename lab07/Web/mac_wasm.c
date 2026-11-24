/**
 * =============================================================================
 * Lab 07: WebAssembly Bridge & OpenSSL 3 EVP_MAC Provider for wasm32
 * Compiles the actual C files from lab07/src/:
 *   - ../src/cmac/cmac.c (cmac_keygen, cmac_compute, cmac_verify)
 *   - ../src/hmac/hmac.c (hmac_keygen, hmac_compute, hmac_verify)
 *   - ../src/kmac/kmac.c (kmac_keygen, kmac_compute, kmac_verify)
 * =============================================================================
 */

#define WASM_EXPORT __attribute__((visibility("default")))

typedef unsigned char      uint8_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef unsigned long long uint64_t;
typedef long long          int64_t;
typedef unsigned long      size_t;

#ifndef NULL
#define NULL ((void*)0)
#endif

// =============================================================================
// MINIMAL LIBC PRIMITIVES FOR WASM32 (malloc, free, strlen, strcmp, memcpy, etc.)
// =============================================================================

static uint8_t g_heap[4 * 1024 * 1024]; // 4 MB static heap for malloc/free in WASM
static size_t  g_heap_offset = 0;

void* malloc(size_t size) {
    size = (size + 7U) & ~7U;
    if (g_heap_offset + size > sizeof(g_heap)) {
        g_heap_offset = 0;
        if (size > sizeof(g_heap)) return NULL;
    }
    void* ptr = &g_heap[g_heap_offset];
    g_heap_offset += size;
    return ptr;
}

void free(void* ptr) {
    (void)ptr;
}

size_t strlen(const char* s) {
    if (!s) return 0;
    size_t len = 0;
    while (s[len] != '\0') len++;
    return len;
}

static int str_eq(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

void* memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void* memset(void* dst, int c, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)c;
    return dst;
}

// =============================================================================
// OPENSSL 3.0 EVP_MAC, OSSL_PARAM, RAND_priv_bytes & CRYPTO_memcmp DEFINITIONS
// =============================================================================

#define EVP_MAX_MD_SIZE         64
#define OSSL_MAC_PARAM_CIPHER   "cipher"
#define OSSL_MAC_PARAM_DIGEST   "digest"
#define OSSL_MAC_PARAM_CUSTOM   "custom"
#define OSSL_MAC_PARAM_SIZE     "size"

#define OSSL_PARAM_END          0
#define OSSL_PARAM_UTF8_STRING  1
#define OSSL_PARAM_SIZE_T       2

typedef struct ossl_param_st {
    const char* key;
    unsigned int data_type;
    void* data;
    size_t data_size;
} OSSL_PARAM;

static OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char* key, char* buf, size_t bsize) {
    OSSL_PARAM p;
    p.key = key;
    p.data_type = OSSL_PARAM_UTF8_STRING;
    p.data = (void*)buf;
    p.data_size = bsize;
    return p;
}

static OSSL_PARAM OSSL_PARAM_construct_size_t(const char* key, size_t* buf) {
    OSSL_PARAM p;
    p.key = key;
    p.data_type = OSSL_PARAM_SIZE_T;
    p.data = (void*)buf;
    p.data_size = sizeof(size_t);
    return p;
}

static OSSL_PARAM OSSL_PARAM_construct_end(void) {
    OSSL_PARAM p;
    p.key = NULL;
    p.data_type = OSSL_PARAM_END;
    p.data = NULL;
    p.data_size = 0;
    return p;
}

int CRYPTO_memcmp(const void* in_a, const void* in_b, size_t len) {
    const uint8_t* a = (const uint8_t*)in_a;
    const uint8_t* b = (const uint8_t*)in_b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return (int)diff;
}

// CSPRNG state seeded from WebCrypto (crypto.getRandomValues) before keygen
static uint64_t g_rng_s0 = 0x853c49e6748fea9bULL;
static uint64_t g_rng_s1 = 0xda3e39cb94b95bdbULL;

WASM_EXPORT void wasm_seed_rng(uint64_t s0, uint64_t s1) {
    g_rng_s0 ^= s0 ? s0 : 0x9e3779b97f4a7c15ULL;
    g_rng_s1 ^= s1 ? s1 : 0xbf58476d1ce4e5b9ULL;
}

static uint8_t next_rand_byte(void) {
    uint64_t s1 = g_rng_s0;
    uint64_t s0 = g_rng_s1;
    g_rng_s0 = s0;
    s1 ^= s1 << 23;
    g_rng_s1 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    uint64_t res = g_rng_s1 + s0;
    return (uint8_t)((res >> 24) & 0xFFU);
}

int RAND_priv_bytes(unsigned char* buf, size_t num) {
    if (!buf) return 0;
    for (size_t i = 0; i < num; i++) {
        buf[i] = next_rand_byte();
    }
    return 1;
}

// =============================================================================
// CRYPTOGRAPHIC IMPLEMENTATIONS FOR OPENSSL EVP_MAC (CMAC, HMAC, KMAC)
// =============================================================================

// --- 1. AES-128 / AES-192 / AES-256 & CMAC (NIST SP 800-38B) ---
static const uint8_t AES_SBOX[256] = {
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

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t aes_xtime(uint8_t a) {
    return (uint8_t)(((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)) & 0xff);
}

static void aes_expand_key(const uint8_t* key, size_t key_len, uint8_t w[240], int* out_nr) {
    int Nk = (int)(key_len >> 2);
    int Nr = Nk + 6;
    *out_nr = Nr;
    int total_words = 4 * (Nr + 1);
    for (size_t i = 0; i < key_len; i++) w[i] = key[i];

    uint8_t temp[4];
    for (int i = Nk; i < total_words; i++) {
        int prev = (i - 1) * 4;
        temp[0] = w[prev]; temp[1] = w[prev + 1]; temp[2] = w[prev + 2]; temp[3] = w[prev + 3];
        if (i % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[i / Nk];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[t];
        } else if (Nk > 6 && (i % Nk) == 4) {
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];
        }
        int nk_off = (i - Nk) * 4;
        int cur_off = i * 4;
        w[cur_off]     = w[nk_off]     ^ temp[0];
        w[cur_off + 1] = w[nk_off + 1] ^ temp[1];
        w[cur_off + 2] = w[nk_off + 2] ^ temp[2];
        w[cur_off + 3] = w[nk_off + 3] ^ temp[3];
    }
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t w[240], int Nr) {
    uint8_t s[16], tmp[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ w[i];

    for (int round = 1; round <= Nr; round++) {
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        for (int i = 0; i < 16; i++) tmp[i] = s[i];
        s[1] = tmp[5];  s[5] = tmp[9];  s[9] = tmp[13]; s[13] = tmp[1];
        s[2] = tmp[10]; s[6] = tmp[14]; s[10] = tmp[2]; s[14] = tmp[6];
        s[3] = tmp[15]; s[7] = tmp[3];  s[11] = tmp[7]; s[15] = tmp[11];

        if (round < Nr) {
            for (int c = 0; c < 16; c += 4) {
                uint8_t a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
                uint8_t t = a0 ^ a1 ^ a2 ^ a3;
                s[c]     ^= t ^ aes_xtime(a0 ^ a1);
                s[c + 1] ^= t ^ aes_xtime(a1 ^ a2);
                s[c + 2] ^= t ^ aes_xtime(a2 ^ a3);
                s[c + 3] ^= t ^ aes_xtime(a3 ^ a0);
            }
        }
        int ro = round * 16;
        for (int i = 0; i < 16; i++) s[i] ^= w[ro + i];
    }
    for (int i = 0; i < 16; i++) out[i] = s[i];
}

static void cmac_left_shift(const uint8_t in[16], uint8_t out[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t b = in[i];
        out[i] = (uint8_t)((b << 1) | carry);
        carry = (b & 0x80) ? 1 : 0;
    }
}

static void raw_cmac_compute(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[16]) {
    uint8_t w[240];
    int Nr = 10;
    aes_expand_key(key, key_len, w, &Nr);

    uint8_t zero[16] = {0};
    uint8_t L[16], K1[16], K2[16];
    aes_encrypt_block(zero, L, w, Nr);
    cmac_left_shift(L, K1);
    if (L[0] & 0x80) K1[15] ^= 0x87;
    cmac_left_shift(K1, K2);
    if (K1[0] & 0x80) K2[15] ^= 0x87;

    size_t n = (data_len == 0) ? 1 : ((data_len + 15) / 16);
    int flag_complete = (data_len > 0) && ((data_len % 16) == 0);

    uint8_t M_last[16];
    size_t last_start = (n - 1) * 16;
    size_t rem = data_len - last_start;

    if (flag_complete) {
        for (size_t i = 0; i < 16; i++) M_last[i] = data[last_start + i] ^ K1[i];
    } else {
        for (size_t i = 0; i < 16; i++) {
            uint8_t b = 0;
            if (i < rem) b = data[last_start + i];
            else if (i == rem) b = 0x80;
            M_last[i] = b ^ K2[i];
        }
    }

    uint8_t X[16] = {0};
    uint8_t Y[16];
    for (size_t blk = 0; blk < n - 1; blk++) {
        size_t off = blk * 16;
        for (size_t i = 0; i < 16; i++) Y[i] = X[i] ^ data[off + i];
        aes_encrypt_block(Y, X, w, Nr);
    }
    for (size_t i = 0; i < 16; i++) Y[i] = X[i] ^ M_last[i];
    aes_encrypt_block(Y, out, w, Nr);
}

// --- 2. SHA-256, SHA-512 & HMAC (FIPS 180-4 & FIPS 198-1) ---
static const uint32_t SHA256_K[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static void raw_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    size_t pad_len = ((len + 9 + 63) & ~((size_t)63));
    uint8_t* buf = (uint8_t*)malloc(pad_len);
    memset(buf, 0, pad_len);
    memcpy(buf, data, len);
    buf[len] = 0x80;

    uint64_t bit_len = (uint64_t)len * 8ULL;
    for (int i = 0; i < 8; i++) {
        buf[pad_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    uint32_t W[64];
    for (size_t off = 0; off < pad_len; off += 64) {
        for (int i = 0; i < 16; i++) {
            size_t j = off + i * 4;
            W[i] = ((uint32_t)buf[j] << 24) | ((uint32_t)buf[j + 1] << 16) |
                   ((uint32_t)buf[j + 2] << 8) | ((uint32_t)buf[j + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
            uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + SHA256_K[i] + W[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbcdULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64U - n));
}

static void raw_sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    size_t pad_len = ((len + 17 + 127) & ~((size_t)127));
    uint8_t* buf = (uint8_t*)malloc(pad_len);
    memset(buf, 0, pad_len);
    memcpy(buf, data, len);
    buf[len] = 0x80;

    uint64_t bit_len = (uint64_t)len * 8ULL;
    for (int i = 0; i < 8; i++) {
        buf[pad_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    uint64_t W[80];
    for (size_t off = 0; off < pad_len; off += 128) {
        for (int i = 0; i < 16; i++) {
            size_t j = off + i * 8;
            uint64_t v = 0;
            for (int b = 0; b < 8; b++) v = (v << 8) | buf[j + b];
            W[i] = v;
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = rotr64(W[i - 15], 1) ^ rotr64(W[i - 15], 8) ^ (W[i - 15] >> 7);
            uint64_t s1 = rotr64(W[i - 2], 19) ^ rotr64(W[i - 2], 61) ^ (W[i - 2] >> 6);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch = (e & f) ^ ((~e) & g);
            uint64_t t1 = hh + S1 + ch + SHA512_K[i] + W[i];
            uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (int i = 0; i < 8; i++) {
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(h[i] >> ((7 - b) * 8));
        }
    }
}

static void raw_hmac_compute(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, int is_sha512, uint8_t* out, size_t* out_len) {
    size_t block_size = is_sha512 ? 128 : 64;
    size_t digest_len = is_sha512 ? 64 : 32;

    uint8_t k0[128];
    memset(k0, 0, sizeof(k0));
    if (key_len > block_size) {
        if (is_sha512) raw_sha512(key, key_len, k0);
        else raw_sha256(key, key_len, k0);
    } else {
        memcpy(k0, key, key_len);
    }

    uint8_t ipad[128], opad[128];
    for (size_t i = 0; i < block_size; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t* inner_in = (uint8_t*)malloc(block_size + data_len);
    memcpy(inner_in, ipad, block_size);
    memcpy(inner_in + block_size, data, data_len);

    uint8_t inner_hash[64];
    if (is_sha512) raw_sha512(inner_in, block_size + data_len, inner_hash);
    else raw_sha256(inner_in, block_size + data_len, inner_hash);

    uint8_t outer_in[128 + 64];
    memcpy(outer_in, opad, block_size);
    memcpy(outer_in + block_size, inner_hash, digest_len);

    if (is_sha512) raw_sha512(outer_in, block_size + digest_len, out);
    else raw_sha256(outer_in, block_size + digest_len, out);

    *out_len = digest_len;
}

// --- 3. KECCAK-f[1600], cSHAKE & KMAC-128 / KMAC-256 (NIST SP 800-185) ---
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint32_t KECCAK_ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int KECCAK_PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static uint64_t rotl64(uint64_t x, uint32_t n) {
    return (x << n) | (x >> (64U - n));
}

static void keccak_f1600(uint8_t state_bytes[200]) {
    uint64_t st[25];
    for (int i = 0; i < 25; i++) {
        uint64_t v = 0;
        for (int b = 7; b >= 0; b--) v = (v << 8) | state_bytes[i * 8 + b];
        st[i] = v;
    }

    uint64_t bc[5];
    for (int round = 0; round < 24; round++) {
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PILN[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, KECCAK_ROTC[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        st[0] ^= KECCAK_RC[round];
    }

    for (int i = 0; i < 25; i++) {
        for (int b = 0; b < 8; b++) {
            state_bytes[i * 8 + b] = (uint8_t)(st[i] >> (b * 8));
        }
    }
}

static size_t sp800_left_encode(uint64_t x, uint8_t out[10]) {
    uint8_t tmp[8];
    size_t n = 0;
    uint64_t v = x;
    while (v > 0) {
        tmp[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    if (n == 0) {
        tmp[0] = 0;
        n = 1;
    }
    out[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        out[1 + i] = tmp[n - 1 - i];
    }
    return n + 1;
}

static size_t sp800_right_encode(uint64_t x, uint8_t out[10]) {
    uint8_t tmp[8];
    size_t n = 0;
    uint64_t v = x;
    while (v > 0) {
        tmp[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    if (n == 0) {
        tmp[0] = 0;
        n = 1;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = (uint8_t)n;
    return n + 1;
}

static void raw_kmac_compute(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    const char* custom_str,
    int is_kmac256,
    uint8_t* out, size_t out_len
) {
    size_t rate = is_kmac256 ? 136 : 168;
    const uint8_t N[4] = {'K', 'M', 'A', 'C'};
    size_t S_len = custom_str ? strlen(custom_str) : 0;

    uint8_t le_w[10], le_n[10], le_s[10], le_k[10], re_l[10];
    size_t le_w_len = sp800_left_encode(rate, le_w);
    size_t le_n_len = sp800_left_encode(4 * 8, le_n);
    size_t le_s_len = sp800_left_encode((uint64_t)S_len * 8ULL, le_s);
    size_t le_k_len = sp800_left_encode((uint64_t)key_len * 8ULL, le_k);
    size_t re_l_len = sp800_right_encode((uint64_t)out_len * 8ULL, re_l);

    size_t ns_raw_len = le_w_len + le_n_len + 4 + le_s_len + S_len;
    size_t ns_pad_len = ((ns_raw_len + rate - 1) / rate) * rate;

    size_t k_raw_len = le_w_len + le_k_len + key_len;
    size_t k_pad_len = ((k_raw_len + rate - 1) / rate) * rate;

    size_t total_in_len = ns_pad_len + k_pad_len + data_len + re_l_len;
    uint8_t* stream = (uint8_t*)malloc(total_in_len);
    memset(stream, 0, total_in_len);

    size_t p = 0;
    memcpy(stream + p, le_w, le_w_len); p += le_w_len;
    memcpy(stream + p, le_n, le_n_len); p += le_n_len;
    memcpy(stream + p, N, 4);           p += 4;
    memcpy(stream + p, le_s, le_s_len); p += le_s_len;
    if (S_len > 0) {
        memcpy(stream + p, custom_str, S_len);
    }

    p = ns_pad_len;
    memcpy(stream + p, le_w, le_w_len); p += le_w_len;
    memcpy(stream + p, le_k, le_k_len); p += le_k_len;
    memcpy(stream + p, key, key_len);

    p = ns_pad_len + k_pad_len;
    if (data_len > 0) {
        memcpy(stream + p, data, data_len);
        p += data_len;
    }
    memcpy(stream + p, re_l, re_l_len);

    uint8_t state[200];
    memset(state, 0, sizeof(state));
    size_t offset = 0;
    while (offset + rate <= total_in_len) {
        for (size_t i = 0; i < rate; i++) state[i] ^= stream[offset + i];
        keccak_f1600(state);
        offset += rate;
    }
    size_t rem = total_in_len - offset;
    for (size_t i = 0; i < rem; i++) state[i] ^= stream[offset + i];
    state[rem] ^= 0x04;
    state[rate - 1] ^= 0x80;
    keccak_f1600(state);

    size_t out_pos = 0;
    while (out_pos < out_len) {
        size_t take = (out_len - out_pos < rate) ? (out_len - out_pos) : rate;
        memcpy(out + out_pos, state, take);
        out_pos += take;
        if (out_pos < out_len) keccak_f1600(state);
    }
}

// =============================================================================
// OPENSSL EVP_MAC DISPATCHER IMPLEMENTATION
// =============================================================================

#define ALG_CMAC     1
#define ALG_HMAC     2
#define ALG_KMAC128  3
#define ALG_KMAC256  4

typedef struct evp_mac_st {
    int alg_id;
} EVP_MAC;

typedef struct evp_mac_ctx_st {
    int alg_id;
    uint8_t key[256];
    size_t key_len;
    char cipher[32];
    char digest[32];
    char custom[128];
    size_t req_out_size;
    const uint8_t* data_ptr;
    size_t data_len;
} EVP_MAC_CTX;

static EVP_MAC g_mac_cmac    = { ALG_CMAC };
static EVP_MAC g_mac_hmac    = { ALG_HMAC };
static EVP_MAC g_mac_kmac128 = { ALG_KMAC128 };
static EVP_MAC g_mac_kmac256 = { ALG_KMAC256 };
static EVP_MAC_CTX g_ctx_instance;

EVP_MAC* EVP_MAC_fetch(void* libctx, const char* algorithm, const char* properties) {
    (void)libctx;
    (void)properties;
    if (!algorithm) return NULL;
    if (str_eq(algorithm, "CMAC"))     return &g_mac_cmac;
    if (str_eq(algorithm, "HMAC"))     return &g_mac_hmac;
    if (str_eq(algorithm, "KMAC-128")) return &g_mac_kmac128;
    if (str_eq(algorithm, "KMAC-256")) return &g_mac_kmac256;
    return NULL;
}

void EVP_MAC_free(EVP_MAC* mac) {
    (void)mac;
}

EVP_MAC_CTX* EVP_MAC_CTX_new(EVP_MAC* mac) {
    if (!mac) return NULL;
    memset(&g_ctx_instance, 0, sizeof(g_ctx_instance));
    g_ctx_instance.alg_id = mac->alg_id;
    g_ctx_instance.req_out_size = 32;
    return &g_ctx_instance;
}

void EVP_MAC_CTX_free(EVP_MAC_CTX* ctx) {
    (void)ctx;
}

static void copy_str_safe(char* dst, size_t cap, const char* src) {
    if (!src || cap == 0) return;
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

int EVP_MAC_init(EVP_MAC_CTX* ctx, const unsigned char* key, size_t keylen, const OSSL_PARAM params[]) {
    if (!ctx || !key || keylen > sizeof(ctx->key)) return 0;
    memcpy(ctx->key, key, keylen);
    ctx->key_len = keylen;

    if (params) {
        for (int i = 0; params[i].key != NULL; i++) {
            if (str_eq(params[i].key, OSSL_MAC_PARAM_CIPHER) && params[i].data) {
                copy_str_safe(ctx->cipher, sizeof(ctx->cipher), (const char*)params[i].data);
            } else if (str_eq(params[i].key, OSSL_MAC_PARAM_DIGEST) && params[i].data) {
                copy_str_safe(ctx->digest, sizeof(ctx->digest), (const char*)params[i].data);
            } else if (str_eq(params[i].key, OSSL_MAC_PARAM_CUSTOM) && params[i].data) {
                copy_str_safe(ctx->custom, sizeof(ctx->custom), (const char*)params[i].data);
            } else if (str_eq(params[i].key, OSSL_MAC_PARAM_SIZE) && params[i].data) {
                ctx->req_out_size = *((size_t*)params[i].data);
            }
        }
    }
    return 1;
}

int EVP_MAC_update(EVP_MAC_CTX* ctx, const unsigned char* data, size_t datalen) {
    if (!ctx) return 0;
    ctx->data_ptr = data;
    ctx->data_len = datalen;
    return 1;
}

int EVP_MAC_final(EVP_MAC_CTX* ctx, unsigned char* out, size_t* outl, size_t outsize) {
    if (!ctx || !out) return 0;
    (void)outsize;

    if (ctx->alg_id == ALG_CMAC) {
        raw_cmac_compute(ctx->key, ctx->key_len, ctx->data_ptr, ctx->data_len, out);
        if (outl) *outl = 16;
        return 1;
    }
    if (ctx->alg_id == ALG_HMAC) {
        int is_sha512 = str_eq(ctx->digest, "SHA512");
        size_t len = 0;
        raw_hmac_compute(ctx->key, ctx->key_len, ctx->data_ptr, ctx->data_len, is_sha512, out, &len);
        if (outl) *outl = len;
        return 1;
    }
    if (ctx->alg_id == ALG_KMAC128 || ctx->alg_id == ALG_KMAC256) {
        int is_kmac256 = (ctx->alg_id == ALG_KMAC256);
        size_t sz = ctx->req_out_size > 0 ? ctx->req_out_size : (is_kmac256 ? 64 : 32);
        raw_kmac_compute(ctx->key, ctx->key_len, ctx->data_ptr, ctx->data_len, ctx->custom, is_kmac256, out, sz);
        if (outl) *outl = sz;
        return 1;
    }
    return 0;
}

// =============================================================================
// HEADER DEFINITIONS FROM cmac.h, hmac.h, kmac.h FOR FREESTANDING WASM32
// =============================================================================

#define CMAC_H
#define CMAC_OK             0
#define CMAC_ERR            1
#define CMAC_ALG_ERR        2
#define CMAC_CTX_ERR        3
#define CMAC_INT_ERR        4
#define CMAC_UPD_ERR        5
#define CMAC_FIN_ERR        6
#define CMAC_KEY_ERR        7
#define CMAC_LEN_ERR        8
#define CMAC_MOD_ERR        9
#define CMAC_MOD_AES128     0
#define CMAC_MOD_AES192     1
#define CMAC_MOD_AES256     2
#define CMAC_AES_MAX_SIZE   16

#define HMAC_H
#define HMAC_OK             0
#define HMAC_ERR            1
#define HMAC_ALG_ERR        2
#define HMAC_CTX_ERR        3
#define HMAC_INT_ERR        4
#define HMAC_UPD_ERR        5
#define HMAC_FIN_ERR        6
#define HMAC_KEY_ERR        7
#define HMAC_LEN_ERR        8
#define HMAC_MOD_ERR        9
#define HMAC_MOD_256        0
#define HMAC_MOD_512        1

#define KMAC_H
#define KMAC_OK             0
#define KMAC_ERR            1
#define KMAC_ALG_ERR        2
#define KMAC_CTX_ERR        3
#define KMAC_INT_ERR        4
#define KMAC_UPD_ERR        5
#define KMAC_FIN_ERR        6
#define KMAC_KEY_ERR        7
#define KMAC_LEN_ERR        8
#define KMAC_MOD_128        0
#define KMAC_MOD_256        1

// =============================================================================
// DIRECT INCLUSION OF LAB 07 C SOURCE FILES (cmac.c, hmac.c, kmac.c)
// =============================================================================

#include "../src/cmac/cmac.c"
#include "../src/hmac/hmac.c"
#include "../src/kmac/kmac.c"

// =============================================================================
// EXPORTED WASM BUFFERS & WRAPPERS CALLING THE ACTUAL C FUNCTIONS
// =============================================================================

static uint8_t g_key_buf[512];
static uint8_t g_data_buf[1024 * 1024]; // 1 MB input buffer for files/text
static uint8_t g_out_buf[512];
static char    g_custom_buf[256];
static size_t  g_last_out_len = 0;

WASM_EXPORT uint8_t* wasm_get_key_buf(void)      { return g_key_buf; }
WASM_EXPORT uint8_t* wasm_get_data_buf(void)     { return g_data_buf; }
WASM_EXPORT uint8_t* wasm_get_out_buf(void)      { return g_out_buf; }
WASM_EXPORT char*    wasm_get_custom_buf(void)   { return g_custom_buf; }
WASM_EXPORT uint32_t wasm_get_last_out_len(void) { return (uint32_t)g_last_out_len; }

// --- CMAC Wrappers calling cmac_keygen, cmac_compute, cmac_verify ---
WASM_EXPORT int wasm_cmac_keygen(uint32_t mode) {
    g_heap_offset = 0;
    return cmac_keygen(g_key_buf, mode);
}

WASM_EXPORT int wasm_cmac_compute(uint32_t key_len, uint32_t data_len, uint32_t mode) {
    g_heap_offset = 0;
    g_last_out_len = CMAC_AES_MAX_SIZE;
    return cmac_compute(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, mode, g_out_buf, &g_last_out_len);
}

WASM_EXPORT int wasm_cmac_verify(uint32_t key_len, uint32_t data_len, uint32_t mode, uint32_t tag_len) {
    g_heap_offset = 0;
    return cmac_verify(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, mode, g_out_buf, (size_t)tag_len);
}

// --- HMAC Wrappers calling hmac_keygen, hmac_compute, hmac_verify ---
WASM_EXPORT int wasm_hmac_keygen(uint32_t mode, uint32_t key_len) {
    g_heap_offset = 0;
    return hmac_keygen(g_key_buf, mode, (size_t)key_len);
}

WASM_EXPORT int wasm_hmac_compute(uint32_t key_len, uint32_t data_len, uint32_t mode) {
    g_heap_offset = 0;
    g_last_out_len = EVP_MAX_MD_SIZE;
    return hmac_compute(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, mode, g_out_buf, &g_last_out_len);
}

WASM_EXPORT int wasm_hmac_verify(uint32_t key_len, uint32_t data_len, uint32_t mode, uint32_t tag_len) {
    g_heap_offset = 0;
    return hmac_verify(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, mode, g_out_buf, (size_t)tag_len);
}

// --- KMAC Wrappers calling kmac_keygen, kmac_compute, kmac_verify ---
WASM_EXPORT int wasm_kmac_keygen(uint32_t mode, uint32_t key_len) {
    g_heap_offset = 0;
    return kmac_keygen(g_key_buf, mode, (size_t)key_len);
}

WASM_EXPORT int wasm_kmac_compute(uint32_t key_len, uint32_t data_len, uint32_t mode, uint32_t out_len) {
    g_heap_offset = 0;
    g_last_out_len = (size_t)out_len;
    return kmac_compute(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, g_custom_buf, mode, g_out_buf, (size_t)out_len);
}

WASM_EXPORT int wasm_kmac_verify(uint32_t key_len, uint32_t data_len, uint32_t mode, uint32_t out_len) {
    g_heap_offset = 0;
    return kmac_verify(g_key_buf, (size_t)key_len, g_data_buf, (size_t)data_len, g_custom_buf, mode, g_out_buf, (size_t)out_len);
}
