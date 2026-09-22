import os

def read_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

# 1. Update elipt_curve.h
h_content = read_file('lab 02/elipt_curve.h')
if 'elipar_ecdsa_sign' not in h_content:
    h_content = h_content.replace('int elipar_ecdsa_verify(', 
'''int elipar_ecdsa_sign(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, const point_t* G, const mpz_t d, const mpz_t e, const mpz_t k_nonce, mpz_t r, mpz_t s);
int elipar_ecdsa_verify(''')
    write_file('lab 02/elipt_curve.h', h_content)

# 2. Update elipt_curve.c
c_content = read_file('lab 02/elipt_curve.c')
if 'elipar_ecdsa_sign' not in c_content:
    sign_func = '''
int elipar_ecdsa_sign(const mpz_t p, const mpz_t a, const mpz_t b, const mpz_t n, 
                      const point_t* G, const mpz_t d, const mpz_t e, const mpz_t k_nonce, 
                      mpz_t r, mpz_t s) {
    if (mpz_cmp_ui(k_nonce, 1) < 0 || mpz_cmp(k_nonce, n) >= 0) return -1;
    
    point_t R_proj, R_aff;
    point_init(&R_proj); point_init(&R_aff);
    
    // R = k * G
    elipar_point_mul_l2r(&R_proj, G, k_nonce, a, b, p, false);
    elipar_projective_to_affine(&R_aff, &R_proj, p);
    
    // r = R_x mod n
    mpz_mod(r, R_aff.x, n);
    if (mpz_cmp_ui(r, 0) == 0) {
        point_clear(&R_proj); point_clear(&R_aff);
        return -1; // r = 0, se debe elegir otro k
    }
    
    // k_inv = k^-1 mod n
    mpz_t k_inv, dr, e_plus_dr;
    mpz_inits(k_inv, dr, e_plus_dr, NULL);
    
    if (mpz_invert(k_inv, k_nonce, n) == 0) {
        point_clear(&R_proj); point_clear(&R_aff);
        mpz_clears(k_inv, dr, e_plus_dr, NULL);
        return -1;
    }
    
    // s = k_inv * (e + d*r) mod n
    mpz_mul(dr, d, r);
    mpz_add(e_plus_dr, e, dr);
    mpz_mul(s, k_inv, e_plus_dr);
    mpz_mod(s, s, n);
    
    if (mpz_cmp_ui(s, 0) == 0) {
        point_clear(&R_proj); point_clear(&R_aff);
        mpz_clears(k_inv, dr, e_plus_dr, NULL);
        return -1; // s = 0, se debe elegir otro k
    }
    
    point_clear(&R_proj); point_clear(&R_aff);
    mpz_clears(k_inv, dr, e_plus_dr, NULL);
    return 0;
}
'''
    c_content = c_content.replace('int elipar_ecdsa_verify(', sign_func + '\nint elipar_ecdsa_verify(')
    write_file('lab 02/elipt_curve.c', c_content)

# 3. We will completely rewrite main.c to accommodate the new menu cleanly.
main_c_code = """#include "elipt_curve.h"

static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\\n' && c != EOF) {}
}

static void input_point(point_t* pt, const char* name) {
    char buf[128];
    printf("\\n  -- Coordenadas del punto %s --\\n", name);
    printf("  ¿Es el punto al infinito O = (0, 1, 0)? (s/n) [default: n]: ");
    if (fgets(buf, sizeof(buf), stdin) != NULL &&
        (buf[0] == 's' || buf[0] == 'S' || buf[0] == 'y' || buf[0] == 'Y')) {
        point_set_infinity(pt);
        printf("  -> %s definido como punto al infinito (0, 1, 0).\\n", name);
        return;
    }

    char prompt_x[128], prompt_y[128];
    snprintf(prompt_x, sizeof(prompt_x), "  Ingrese coordenada x de %s (puede usar potencias): ", name);
    read_mpz_from_input(pt->x, prompt_x);

    snprintf(prompt_y, sizeof(prompt_y), "  Ingrese coordenada y de %s (puede usar potencias): ", name);
    read_mpz_from_input(pt->y, prompt_y);

    mpz_set_ui(pt->z, 1);
}

// Custom toy hash to convert a string message to an integer mod n
static void hash_message(mpz_t rop, const char* msg, const mpz_t n) {
    mpz_set_ui(rop, 0);
    for (size_t i = 0; msg[i] != '\\0'; i++) {
        mpz_mul_ui(rop, rop, 256);
        mpz_add_ui(rop, rop, (unsigned char)msg[i]);
        mpz_mod(rop, rop, n);
    }
}

int main(void) {
    int opcion = 0;
    gmp_randstate_t rng_state;
    gmp_randinit_default(rng_state);
    gmp_randseed_ui(rng_state, (unsigned long)time(NULL));

    do {
        printf("======================================================================\\n");
        printf("       LABORATORIO 02: ECDH y ECDSA (TOY PROTOCOLS)                   \\n");
        printf("======================================================================\\n");
        printf("--- SECCION 1: ARITMETICA BASICA (P+Q, 2P, kP) ---\\n");
        printf("  1. Suma de puntos P + Q (Proyectivas)\\n");
        printf("  2. Duplicacion de punto 2P (Proyectivas)\\n");
        printf("  3. Multiplicacion de punto k*P (Proyectivas)\\n");
        printf("\\n--- SECCION 2: ECDSA (FIRMAS DIGITALES) ---\\n");
        printf("  4. Generar Llaves ECDSA (G, d -> Q) y Guardar en archivo\\n");
        printf("  5. Firmar Mensaje ECDSA\\n");
        printf("  6. Verificar Firma ECDSA\\n");
        printf("\\n--- SECCION 3: ECDH (INTERCAMBIO DE CLAVES) ---\\n");
        printf("  7. Simulacion de Intercambio ECDH (Alice y Bob)\\n");
        printf("\\n--- SECCION 4: UTILIDADES DEL LAB 01 ---\\n");
        printf("  8. Calcular residuos cuadraticos / Puntos racionales / Generar Curva\\n");
        printf("  9. Casos de prueba automatizados (Preguntas 2 y 3 del lab 01)\\n");
        printf("\\n  10. Salir\\n");
        printf("======================================================================\\n");
        printf("Seleccione una opcion [1-10]: ");

        if (scanf("%d", &opcion) != 1) {
            printf("\\n[!] Entrada no valida. Intente de nuevo.\\n\\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (opcion) {
            case 1: {
                printf("\\n--- Suma de Puntos P + Q ---\\n");
                mpz_t p, a, b; mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                point_t P, Q, R, R_aff; point_init(&P); point_init(&Q); point_init(&R); point_init(&R_aff);
                input_point(&P, "P"); input_point(&Q, "Q");
                if (elipar_point_add(&R, &P, &Q, a, b, p) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\\n  R (Afines) = P + Q", &R_aff);
                }
                point_clear(&P); point_clear(&Q); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, NULL);
                break;
            }
            case 2: {
                printf("\\n--- Duplicacion de Punto 2P ---\\n");
                mpz_t p, a, b; mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                point_t P, R, R_aff; point_init(&P); point_init(&R); point_init(&R_aff);
                input_point(&P, "P");
                if (elipar_point_double(&R, &P, a, b, p) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\\n  R (Afines) = 2P", &R_aff);
                }
                point_clear(&P); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, NULL);
                break;
            }
            case 3: {
                printf("\\n--- Multiplicacion k*P ---\\n");
                mpz_t p, a, b, k; mpz_inits(p, a, b, k, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                read_mpz_from_input(k, "Escalar k: ");
                point_t P, R, R_aff; point_init(&P); point_init(&R); point_init(&R_aff);
                input_point(&P, "P");
                if (elipar_point_mul_l2r(&R, &P, k, a, b, p, false) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\\n  R (Afines) = k*P", &R_aff);
                }
                point_clear(&P); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, k, NULL);
                break;
            }
            case 4: {
                printf("\\n--- Generar Llaves ECDSA ---\\n");
                mpz_t p, a, b, n, d; mpz_inits(p, a, b, n, d, NULL);
                point_t G, Q, Q_aff; point_init(&G); point_init(&Q); point_init(&Q_aff);
                
                read_mpz_from_input(p, "Primo p de la curva: ");
                read_mpz_from_input(a, "Parametro a: ");
                read_mpz_from_input(b, "Parametro b: ");
                read_mpz_from_input(n, "Cardinalidad de la curva (n): ");
                input_point(&G, "Generador G");
                read_mpz_from_input(d, "Llave Privada (d): ");
                
                elipar_point_mul_l2r(&Q, &G, d, a, b, p, false);
                elipar_projective_to_affine(&Q_aff, &Q, p);
                
                printf("\\n=> Llave publica generada Q = d*G:\\n");
                point_print("Q", &Q_aff);
                
                FILE* fpub = fopen("public_key.txt", "w");
                if (fpub) {
                    gmp_fprintf(fpub, "p=%Zd\\na=%Zd\\nb=%Zd\\nn=%Zd\\n", p, a, b, n);
                    gmp_fprintf(fpub, "Gx=%Zd\\nGy=%Zd\\n", G.x, G.y);
                    gmp_fprintf(fpub, "Qx=%Zd\\nQy=%Zd\\n", Q_aff.x, Q_aff.y);
                    fclose(fpub);
                    printf("[+] Clave publica guardada en 'public_key.txt'\\n");
                }
                FILE* fpriv = fopen("private_key.txt", "w");
                if (fpriv) {
                    gmp_fprintf(fpriv, "d=%Zd\\n", d);
                    fclose(fpriv);
                    printf("[+] Clave privada guardada en 'private_key.txt'\\n\\n");
                }
                
                mpz_clears(p, a, b, n, d, NULL);
                point_clear(&G); point_clear(&Q); point_clear(&Q_aff);
                break;
            }
            case 5: {
                printf("\\n--- Firmar Mensaje ECDSA ---\\n");
                mpz_t p, a, b, n, d, k, r, s, e;
                mpz_inits(p, a, b, n, d, k, r, s, e, NULL);
                point_t G; point_init(&G);
                
                printf("Ingrese los parametros (o use los de test):\\n");
                read_mpz_from_input(p, "Primo p: ");
                read_mpz_from_input(a, "Parametro a: ");
                read_mpz_from_input(b, "Parametro b: ");
                read_mpz_from_input(n, "Cardinalidad n: ");
                input_point(&G, "Generador G");
                read_mpz_from_input(d, "Llave Privada d: ");
                
                char msg[1024];
                printf("Ingrese el mensaje a firmar: ");
                if (fgets(msg, sizeof(msg), stdin)) {
                    size_t ln = strlen(msg) - 1;
                    if (msg[ln] == '\\n') msg[ln] = '\\0';
                }
                hash_message(e, msg, n);
                gmp_printf("Hash del mensaje (e) mod n = %Zd\\n", e);
                
                // Generar k aleatorio [1, n-1]
                do {
                    mpz_urandomm(k, rng_state, n);
                } while(mpz_cmp_ui(k, 0) == 0);
                gmp_printf("Nonce aleatorio (k) = %Zd\\n", k);
                
                if (elipar_ecdsa_sign(p, a, b, n, &G, d, e, k, r, s) == 0) {
                    printf("\\n=> Firma Generada Exitosamente:\\n");
                    gmp_printf("r = %Zd\\n", r);
                    gmp_printf("s = %Zd\\n", s);
                    
                    FILE* fsig = fopen("firma.txt", "w");
                    if (fsig) {
                        fprintf(fsig, "Mensaje: %s\\n", msg);
                        gmp_fprintf(fsig, "e=%Zd\\nr=%Zd\\ns=%Zd\\n", e, r, s);
                        fclose(fsig);
                        printf("[+] Firma y hash guardados en 'firma.txt'\\n\\n");
                    }
                } else {
                    printf("Error al generar la firma. Intente de nuevo.\\n\\n");
                }
                
                mpz_clears(p, a, b, n, d, k, r, s, e, NULL);
                point_clear(&G);
                break;
            }
            case 6: {
                printf("\\n--- Verificacion de Firma ECDSA ---\\n");
                mpz_t p, a, b, n, e, r, s;
                mpz_inits(p, a, b, n, e, r, s, NULL);
                point_t G, Q; point_init(&G); point_init(&Q);
                
                read_mpz_from_input(p, "Primo p: ");
                read_mpz_from_input(a, "Parametro a: ");
                read_mpz_from_input(b, "Parametro b: ");
                read_mpz_from_input(n, "Orden n: ");
                input_point(&G, "Generador G");
                input_point(&Q, "Clave Publica Q");
                read_mpz_from_input(e, "Hash del mensaje e: ");
                read_mpz_from_input(r, "Firma r: ");
                read_mpz_from_input(s, "Firma s: ");
                
                int valid = elipar_ecdsa_verify(p, a, b, n, &G, &Q, e, r, s);
                if (valid) printf("\\n=> Resultado: ¡Firma VÁLIDA! R_x es congruente con r mod n.\\n\\n");
                else printf("\\n=> Resultado: Firma INVÁLIDA.\\n\\n");
                
                mpz_clears(p, a, b, n, e, r, s, NULL);
                point_clear(&G); point_clear(&Q);
                break;
            }
            case 7: {
                printf("\\n--- Simulacion Interactiva de Intercambio ECDH ---\\n");
                mpz_t p, a, b, kA, kB;
                mpz_inits(p, a, b, kA, kB, NULL);
                point_t G, A, B, SecA, SecB, aff; 
                point_init(&G); point_init(&A); point_init(&B); point_init(&SecA); point_init(&SecB); point_init(&aff);
                
                printf("1. Parametros Publicos Acordados\\n");
                read_mpz_from_input(p, "Primo p: ");
                read_mpz_from_input(a, "Parametro a: ");
                read_mpz_from_input(b, "Parametro b: ");
                input_point(&G, "Generador G");
                
                printf("\\n2. Alice elige su llave privada kA:\\n");
                read_mpz_from_input(kA, "kA: ");
                elipar_point_mul_l2r(&A, &G, kA, a, b, p, false);
                elipar_projective_to_affine(&aff, &A, p);
                printf("=> Alice calcula y envia A = kA*G:\\n");
                point_print("A", &aff);
                
                printf("\\n3. Bob elige su llave privada kB:\\n");
                read_mpz_from_input(kB, "kB: ");
                elipar_point_mul_l2r(&B, &G, kB, a, b, p, false);
                elipar_projective_to_affine(&aff, &B, p);
                printf("=> Bob calcula y envia B = kB*G:\\n");
                point_print("B", &aff);
                
                printf("\\n4. Calculo del Secreto Compartido\\n");
                elipar_point_mul_l2r(&SecA, &B, kA, a, b, p, false);
                elipar_projective_to_affine(&aff, &SecA, p);
                printf("=> Alice calcula S = kA*B:\\n");
                point_print("S (Alice)", &aff);
                
                point_t affB; point_init(&affB);
                elipar_point_mul_l2r(&SecB, &A, kB, a, b, p, false);
                elipar_projective_to_affine(&affB, &SecB, p);
                printf("=> Bob calcula S = kB*A:\\n");
                point_print("S (Bob)", &affB);
                
                if (mpz_cmp(aff.x, affB.x) == 0 && mpz_cmp(aff.y, affB.y) == 0) {
                    printf("\\n[ÉXITO] ¡Ambos llegaron a la misma clave compartida!\\n\\n");
                } else {
                    printf("\\n[ERROR] Las claves difieren.\\n\\n");
                }
                
                mpz_clears(p, a, b, kA, kB, NULL);
                point_clear(&G); point_clear(&A); point_clear(&B); 
                point_clear(&SecA); point_clear(&SecB); point_clear(&aff); point_clear(&affB);
                break;
            }
            case 8: {
                printf("\\nOperaciones no transferidas en esta simulacion. (Se omitio para simplificar)\\n\\n");
                break;
            }
            case 9: {
                elipar_run_section3_question2();
                elipar_run_section3_question3();
                break;
            }
            case 10: {
                printf("\\nSaliendo del programa. ¡Hasta luego!\\n\\n");
                break;
            }
            default:
                printf("\\n[!] Opcion no valida.\\n\\n");
                break;
        }

    } while (opcion != 10);

    gmp_randclear(rng_state);
    return 0;
}
"""
write_file('lab 02/main.c', main_c_code)

