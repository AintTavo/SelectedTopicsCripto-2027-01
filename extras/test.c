
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

int main() {
    mpz_t res, p, gen, alpha;
    mpz_inits(res, p, gen, alpha, NULL);

    mpz_set_ui(p,37);
    mpz_set_ui(gen, 2);
    mpz_set_ui(alpha, 35);

    for (int i = 0 ; i < 37 ; i++) {
        mpz_pow_ui(res, gen, i);
        mpz_mod(res, res, p);
        if (mpz_cmp(res, alpha) == 0){
            printf("d = %i", i);
        }
    }
    mpz_clears(res, gen, alpha, p, NULL);
    return 0;
}