#define _GNU_SOURCE
#include <stdio.h>
#include <gmp.h>

int main(){
    mpz_t tmp1, tmp2,p,x1, x2, r, s1, s2;
    mpz_inits(tmp1, tmp2, p, x1, x2, r, s1, s2, NULL);
    mpz_set_ui(p,36);
    mpz_set_ui(x1,9);
    mpz_set_ui(x2,20);
    mpz_set_ui(r,13);
    mpz_set_ui(s1,34);
    mpz_set_ui(s2,35);

    mpz_invert(s1,s1, p);
    mpz_invert(s2,s1, p);

    mpz_sub(tmp1, s1, s2);
    mpz_mul(tmp1, r, s1);

    mpz_invert(tmp1, tmp1, p);

    mpz_mul(x1, x1, s1);
    mpz_mul(x2, x2, s2);
    mpz_sub(tmp2, x1, x2);
    mpz_mul(tmp1, tmp1, tmp2);
    mpz_mod(tmp1, tmp1, p);

    gmp_printf("d = %i",tmp1);
    
    mpz_clears(tmp1, tmp2,p,x1, x2, r, s1, s2, NULL);
}