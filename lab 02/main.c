#include "elipt_curve.h"

static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

static void input_point(point_t* pt, const char* name) {
    char buf[128];
    printf("\n  -- Coordenadas del punto %s --\n", name);
    printf("  ¿Es el punto al infinito O = (0, 1, 0)? (s/n) [default: n]: ");
    if (fgets(buf, sizeof(buf), stdin) != NULL &&
        (buf[0] == 's' || buf[0] == 'S' || buf[0] == 'y' || buf[0] == 'Y')) {
        point_set_infinity(pt);
        printf("  -> %s definido como punto al infinito (0, 1, 0).\n", name);
        return;
    }

    char prompt_x[128], prompt_y[128];
    snprintf(prompt_x, sizeof(prompt_x), "  Ingrese coordenada x de %s (puede usar potencias): ", name);
    read_mpz_from_input(pt->x, prompt_x);

    snprintf(prompt_y, sizeof(prompt_y), "  Ingrese coordenada y de %s (puede usar potencias): ", name);
    read_mpz_from_input(pt->y, prompt_y);

    mpz_set_ui(pt->z, 1);
}

// Generador de Hash basico (Toy) para firmas: Convierte mensaje ASCII a entero mod n
static void hash_message(mpz_t rop, const char* msg, const mpz_t n) {
    mpz_set_ui(rop, 0);
    for (size_t i = 0; msg[i] != '\0'; i++) {
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
        printf("======================================================================\n");
        printf("       LABORATORIO 02: ECDH y ECDSA (TOY PROTOCOLS EN C)              \n");
        printf("======================================================================\n");
        printf("--- SECCION 1: ARITMETICA BASICA ---\n");
        printf("  1. Suma de puntos P + Q (Proyectivas)\n");
        printf("  2. Duplicacion de punto 2P (Proyectivas)\n");
        printf("  3. Multiplicacion de punto k*P (Proyectivas L2R)\n");
        printf("\n--- SECCION 2: ECDSA (FIRMAS DIGITALES) ---\n");
        printf("  4. Generar Llaves ECDSA (Genera y guarda en archivo txt)\n");
        printf("  5. Firmar Mensaje ECDSA (Genera y guarda firma en archivo txt)\n");
        printf("  6. Verificar Firma ECDSA\n");
        printf("\n--- SECCION 3: ECDH (SIMULACION INTERACTIVA) ---\n");
        printf("  7. Simulacion Interactiva de ECDH con Compañero\n");
        printf("\n  8. Salir\n");
        printf("======================================================================\n");
        printf("Seleccione una opcion [1-8]: ");

        if (scanf("%d", &opcion) != 1) {
            printf("\n[!] Entrada no valida. Intente de nuevo.\n\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (opcion) {
            case 1: {
                printf("\n--- Suma de Puntos P + Q ---\n");
                mpz_t p, a, b; mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                point_t P, Q, R, R_aff; point_init(&P); point_init(&Q); point_init(&R); point_init(&R_aff);
                input_point(&P, "P"); input_point(&Q, "Q");
                if (elipar_point_add(&R, &P, &Q, a, b, p) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\n  R (Afines) = P + Q", &R_aff);
                }
                point_clear(&P); point_clear(&Q); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, NULL);
                break;
            }
            case 2: {
                printf("\n--- Duplicacion de Punto 2P ---\n");
                mpz_t p, a, b; mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                point_t P, R, R_aff; point_init(&P); point_init(&R); point_init(&R_aff);
                input_point(&P, "P");
                if (elipar_point_double(&R, &P, a, b, p) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\n  R (Afines) = 2P", &R_aff);
                }
                point_clear(&P); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, NULL);
                break;
            }
            case 3: {
                printf("\n--- Multiplicacion k*P ---\n");
                mpz_t p, a, b, k; mpz_inits(p, a, b, k, NULL);
                read_mpz_from_input(p, "Primo p: "); read_mpz_from_input(a, "Parametro a: "); read_mpz_from_input(b, "Parametro b: ");
                read_mpz_from_input(k, "Escalar k: ");
                point_t P, R, R_aff; point_init(&P); point_init(&R); point_init(&R_aff);
                input_point(&P, "P");
                if (elipar_point_mul_l2r(&R, &P, k, a, b, p, false) == 0) {
                    elipar_projective_to_affine(&R_aff, &R, p);
                    point_print("\n  R (Afines) = k*P", &R_aff);
                }
                point_clear(&P); point_clear(&R); point_clear(&R_aff);
                mpz_clears(p, a, b, k, NULL);
                break;
            }
            case 4: {
                printf("\n--- Generar Llaves ECDSA ---\n");
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
                
                printf("\n=> Llave publica generada Q = d*G:\n");
                point_print("Q", &Q_aff);
                
                FILE* fpub = fopen("public_key.txt", "w");
                if (fpub) {
                    gmp_fprintf(fpub, "p=%Zd\na=%Zd\nb=%Zd\nn=%Zd\n", p, a, b, n);
                    gmp_fprintf(fpub, "Gx=%Zd\nGy=%Zd\n", G.x, G.y);
                    gmp_fprintf(fpub, "Qx=%Zd\nQy=%Zd\n", Q_aff.x, Q_aff.y);
                    fclose(fpub);
                    printf("[+] Clave publica guardada en 'public_key.txt'\n");
                } else {
                    printf("[-] Error guardando 'public_key.txt'\n");
                }

                FILE* fpriv = fopen("private_key.txt", "w");
                if (fpriv) {
                    gmp_fprintf(fpriv, "d=%Zd\n", d);
                    fclose(fpriv);
                    printf("[+] Clave privada guardada en 'private_key.txt'\n\n");
                }
                
                mpz_clears(p, a, b, n, d, NULL);
                point_clear(&G); point_clear(&Q); point_clear(&Q_aff);
                break;
            }
            case 5: {
                printf("\n--- Firmar Mensaje ECDSA ---\n");
                mpz_t p, a, b, n, d, k, r, s, e;
                mpz_inits(p, a, b, n, d, k, r, s, e, NULL);
                point_t G; point_init(&G);
                
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
                    if (msg[ln] == '\n') msg[ln] = '\0';
                }
                hash_message(e, msg, n);
                gmp_printf("=> Hash del mensaje (e) calculado mod n = %Zd\n", e);
                
                do {
                    mpz_urandomm(k, rng_state, n);
                } while(mpz_cmp_ui(k, 0) == 0);
                
                if (elipar_ecdsa_sign(p, a, b, n, &G, d, e, k, r, s) == 0) {
                    printf("\n=> Firma Generada Exitosamente:\n");
                    gmp_printf("r = %Zd\n", r);
                    gmp_printf("s = %Zd\n", s);
                    
                    FILE* fsig = fopen("firma.txt", "w");
                    if (fsig) {
                        fprintf(fsig, "Mensaje: %s\n", msg);
                        gmp_fprintf(fsig, "e=%Zd\nr=%Zd\ns=%Zd\n", e, r, s);
                        fclose(fsig);
                        printf("[+] Firma y hash guardados en 'firma.txt'\n\n");
                    }
                } else {
                    printf("Error al generar la firma. Intente de nuevo.\n\n");
                }
                
                mpz_clears(p, a, b, n, d, k, r, s, e, NULL);
                point_clear(&G);
                break;
            }
            case 6: {
                printf("\n--- Verificacion de Firma ECDSA ---\n");
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
                if (valid) printf("\n=> Resultado: ¡Firma VÁLIDA! R_x es congruente con r mod n.\n\n");
                else printf("\n=> Resultado: Firma INVÁLIDA.\n\n");
                
                mpz_clears(p, a, b, n, e, r, s, NULL);
                point_clear(&G); point_clear(&Q);
                break;
            }
            case 7: {
                printf("\n--- Simulacion ECDH con Compañero ---\n");
                printf("Este flujo emula el protocolo descrito en el PDF del Lab 02.\n\n");
                
                int modo;
                printf("Escoge tu rol:\n 1. Soy Alice (Iniciador)\n 2. Soy Bob (Receptor)\nRol [1-2]: ");
                if(scanf("%d", &modo) != 1) modo = 1;
                clear_input_buffer();
                
                mpz_t p, a, b;
                mpz_inits(p, a, b, NULL);
                point_t G; point_init(&G);
                
                printf("\n[PASO 1]: Acuerden y compartan los parametros de la curva (p, a, b, G):\n");
                read_mpz_from_input(p, "Primo p: ");
                read_mpz_from_input(a, "Parametro a: ");
                read_mpz_from_input(b, "Parametro b: ");
                input_point(&G, "Generador G");
                
                mpz_t my_k, his_k_result_x, his_k_result_y;
                mpz_inits(my_k, his_k_result_x, his_k_result_y, NULL);
                
                printf("\n[PASO 2]: Elige tu secreto aleatorio:\n");
                read_mpz_from_input(my_k, "Mi clave privada secreta (ej. kA o kB): ");
                
                point_t MyPub, MyPub_aff; point_init(&MyPub); point_init(&MyPub_aff);
                elipar_point_mul_l2r(&MyPub, &G, my_k, a, b, p, false);
                elipar_projective_to_affine(&MyPub_aff, &MyPub, p);
                
                printf("\n=> RESULTADO: Comparte esta Clave Publica con tu compañero:\n");
                point_print("Mi Clave Publica", &MyPub_aff);
                
                printf("\n[PASO 3]: Ingresa la Clave Publica que recibiste de tu compañero:\n");
                point_t HisPub; point_init(&HisPub);
                input_point(&HisPub, "Clave Publica del compañero");
                
                point_t SharedSecret, SharedSecret_aff; 
                point_init(&SharedSecret); point_init(&SharedSecret_aff);
                
                elipar_point_mul_l2r(&SharedSecret, &HisPub, my_k, a, b, p, false);
                elipar_projective_to_affine(&SharedSecret_aff, &SharedSecret, p);
                
                printf("\n=> [ÉXITO] SECRETO COMPARTIDO CALCULADO:\n");
                point_print("Shared Secret", &SharedSecret_aff);
                printf("\nPreguntale a tu compañero si obtuvo el mismo Secreto Compartido. Deberian ser exactamente iguales!\n\n");
                
                mpz_clears(p, a, b, my_k, his_k_result_x, his_k_result_y, NULL);
                point_clear(&G); point_clear(&MyPub); point_clear(&MyPub_aff);
                point_clear(&HisPub); point_clear(&SharedSecret); point_clear(&SharedSecret_aff);
                break;
            }
            case 8: {
                printf("\nSaliendo del programa. ¡Hasta luego!\n\n");
                break;
            }
            default:
                printf("\n[!] Opcion no valida.\n\n");
                break;
        }

    } while (opcion != 8);

    gmp_randclear(rng_state);
    return 0;
}
