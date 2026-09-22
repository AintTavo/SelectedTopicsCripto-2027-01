#include "elipt_curve.h"

int main() {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    printf("=== PRUEBAS ALGORITMOS L2R y R2L ===\n");
    mpz_t p, a, b, k;
    mpz_inits(p, a, b, k, NULL);
    
    // Curva 1: secp256k1 reducida o aleatoria
    // Usaremos valores pequeños para pruebas con iteraciones legibles
    mpz_set_ui(p, 97);
    mpz_set_ui(a, 2);
    mpz_set_ui(b, 3);
    
    point_t P, R1, R2;
    point_init(&P); point_init(&R1); point_init(&R2);
    
    // Punto P=(3, 6) en y^2 = x^3 + 2x + 3 mod 97? 
    // 3^3 + 2*3 + 3 = 27 + 6 + 3 = 36. 6^2 = 36 mod 97. Si.
    point_set_ui(&P, 3, 6, 1);
    
    unsigned long ks[] = { 5, 10, 15, 20, 25 };
    
    for (int i=0; i<5; i++) {
        mpz_set_ui(k, ks[i]);
        printf("\n--- Test %d: k = %lu ---\n", i+1, ks[i]);
        printf("Punto P = (3, 6). Curva: y^2 = x^3 + 2x + 3 mod 97\n");
        printf(">> Algoritmo R2L:\n");
        elipar_point_mul_r2l(&R1, &P, k, a, b, p, true);
        printf(">> Algoritmo L2R:\n");
        elipar_point_mul_l2r(&R2, &P, k, a, b, p, true);
        
        point_t aff1, aff2;
        point_init(&aff1); point_init(&aff2);
        elipar_projective_to_affine(&aff1, &R1, p);
        elipar_projective_to_affine(&aff2, &R2, p);
        
        gmp_printf("Resultado R2L: (%Zd, %Zd)\n", aff1.x, aff1.y);
        gmp_printf("Resultado L2R: (%Zd, %Zd)\n", aff2.x, aff2.y);
        point_clear(&aff1); point_clear(&aff2);
    }
    
    printf("\n=== SIMULACION ECDH ===\n");
    // p = 251, a=2, b=3, P=(3,6)? 
    // y^2 = 36. 251 mod... wait, lets generate a 128 bit curve.
    mpz_t p_large, a_large, b_large;
    mpz_inits(p_large, a_large, b_large, NULL);
    elipar_generate_curve(p_large, a_large, b_large, 128, state);
    
    // Find a generator point G. We can just pick x and find y.
    point_t G; point_init(&G);
    mpz_t x_val, rhs, y_val;
    mpz_inits(x_val, rhs, y_val, NULL);
    
    // Find a valid point
    for(unsigned long x=1; x<1000; x++) {
        mpz_set_ui(x_val, x);
        mpz_powm_ui(rhs, x_val, 3, p_large);
        mpz_t tmp; mpz_init(tmp);
        mpz_mul(tmp, a_large, x_val);
        mpz_add(rhs, rhs, tmp);
        mpz_add(rhs, rhs, b_large);
        mpz_mod(rhs, rhs, p_large);
        
        // Check if QR. We can use legendre symbol.
        if (mpz_legendre(rhs, p_large) == 1) {
            // Find root using Tonelli-Shanks? We don't have it implemented.
            // Let's just generate P with a random y, then find b.
            // Curve: y^2 = x^3 + ax + b => b = y^2 - x^3 - ax
            mpz_set_ui(x_val, 5);
            mpz_set_ui(y_val, 7);
            
            mpz_powm_ui(rhs, y_val, 2, p_large); // y^2
            mpz_t x3, ax; mpz_inits(x3, ax, NULL);
            mpz_powm_ui(x3, x_val, 3, p_large);
            mpz_mul(ax, a_large, x_val);
            mpz_sub(b_large, rhs, x3);
            mpz_sub(b_large, b_large, ax);
            mpz_mod(b_large, b_large, p_large);
            
            point_set_mpz(&G, x_val, y_val, x_val);
            mpz_set_ui(G.z, 1);
            mpz_clears(x3, ax, tmp, NULL);
            break;
        }
        mpz_clear(tmp);
    }
    
    gmp_printf("Parametros ECDH acordados:\np = %Zd\na = %Zd\nb = %Zd\nG = (%Zd, %Zd)\n", p_large, a_large, b_large, G.x, G.y);
    
    mpz_t kA, kB;
    mpz_inits(kA, kB, NULL);
    mpz_urandomm(kA, state, p_large);
    mpz_urandomm(kB, state, p_large);
    
    gmp_printf("\nAlice elige kA secreta: %Zd\n", kA);
    gmp_printf("Bob elige kB secreta: %Zd\n", kB);
    
    point_t A, B, SecA, SecB, affA, affB, affSecA, affSecB;
    point_init(&A); point_init(&B); point_init(&SecA); point_init(&SecB);
    point_init(&affA); point_init(&affB); point_init(&affSecA); point_init(&affSecB);
    
    elipar_point_mul_l2r(&A, &G, kA, a_large, b_large, p_large, false);
    elipar_projective_to_affine(&affA, &A, p_large);
    gmp_printf("\nAlice calcula y comparte A = kA * G:\n  A = (%Zd, %Zd)\n", affA.x, affA.y);
    
    elipar_point_mul_l2r(&B, &G, kB, a_large, b_large, p_large, false);
    elipar_projective_to_affine(&affB, &B, p_large);
    gmp_printf("\nBob calcula y comparte B = kB * G:\n  B = (%Zd, %Zd)\n", affB.x, affB.y);
    
    // Alice computes SecA = kA * B
    // B is in projective coords, which is fine since our functions handle projective inputs
    elipar_point_mul_l2r(&SecA, &B, kA, a_large, b_large, p_large, false);
    elipar_projective_to_affine(&affSecA, &SecA, p_large);
    gmp_printf("\nAlice calcula el secreto S = kA * B:\n  S = (%Zd, %Zd)\n", affSecA.x, affSecA.y);
    
    // Bob computes SecB = kB * A
    elipar_point_mul_l2r(&SecB, &A, kB, a_large, b_large, p_large, false);
    elipar_projective_to_affine(&affSecB, &SecB, p_large);
    gmp_printf("\nBob calcula el secreto S = kB * A:\n  S = (%Zd, %Zd)\n", affSecB.x, affSecB.y);
    
    if (mpz_cmp(affSecA.x, affSecB.x) == 0 && mpz_cmp(affSecA.y, affSecB.y) == 0) {
        printf("\n=> ¡Las claves coinciden! El ECDH fue exitoso.\n");
    } else {
        printf("\n=> Error: Las claves no coinciden.\n");
    }
    
    mpz_clears(p, a, b, k, p_large, a_large, b_large, x_val, rhs, y_val, kA, kB, NULL);
    point_clear(&P); point_clear(&R1); point_clear(&R2); point_clear(&G);
    point_clear(&A); point_clear(&B); point_clear(&SecA); point_clear(&SecB);
    point_clear(&affA); point_clear(&affB); point_clear(&affSecA); point_clear(&affSecB);
    gmp_randclear(state);
    
    return 0;
}
