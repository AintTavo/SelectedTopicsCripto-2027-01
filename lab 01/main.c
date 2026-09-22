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

int main(void) {
    int opcion = 0;
    gmp_randstate_t rng_state;
    gmp_randinit_default(rng_state);
    gmp_randseed_ui(rng_state, (unsigned long)time(NULL));

    do {
        printf("======================================================================\n");
        printf("       LABORATORIO 01: CURVAS ELIPTICAS Y ARITMETICA GMP (IPN)        \n");
        printf("======================================================================\n");
        printf("--- SECCION 1: FUNCIONES PRELIMINARES ---\n");
        printf("  1. Calcular residuos cuadraticos y sus raices mod p (Ex. 1)\n");
        printf("  2. Calcular y contar puntos racionales de curva eliptica (Ex. 2)\n");
        printf("\n--- SECCION 2: ARITMETICA DE CURVAS ELIPTICAS (GMP BIG INT) ---\n");
        printf("  3. Generar primo aleatorio de n bits y curva no-singular (Ex. 1)\n");
        printf("  4. Suma de puntos P + Q donde P != +-Q (Ex. 2)\n");
        printf("  5. Duplicacion de punto 2P (Ex. 3)\n");
        printf("\n--- SECCION 3: CASOS DE PRUEBA Y PREGUNTAS DEL LAB ---\n");
        printf("  6. Pregunta 2: Generar curvas para 16, 32, 64, 512, 1024 y 2048 bits\n");
        printf("  7. Pregunta 3: Ejecutar suite de casos (a, b, c, d) para P+Q, 2P y 2Q\n");
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
                mpz_t p;
                mpz_init(p);
                printf("\n--- Ejercicio 1.1: Residuos Cuadraticos y Raices Modulo p ---\n");
                read_mpz_from_input(p, "Ingrese el primo p > 3 (ej. 31 o 2^8 + 1): ");

                if (mpz_cmp_ui(p, 3) <= 0) {
                    printf("Error: p debe ser mayor a 3.\n\n");
                    mpz_clear(p);
                    break;
                }

                qr_table_t* table = elipar_quadratic_residue(p);
                if (table != NULL) {
                    elipar_qr_free(table);
                }
                mpz_clear(p);
                break;
            }

            case 2: {
                mpz_t p, a, b;
                mpz_inits(p, a, b, NULL);
                int destino = 0;
                char filename[256];

                printf("\n--- Ejercicio 1.2: Puntos Racionales de Curva: y^2 = x^3 + ax + b (mod p) ---\n");
                read_mpz_from_input(p, "Ingrese el primo p > 3 (ej. 31): ");
                if (mpz_cmp_ui(p, 3) <= 0) {
                    printf("Error: p debe ser mayor a 3.\n\n");
                    mpz_clears(p, a, b, NULL);
                    break;
                }

                read_mpz_from_input(a, "Ingrese el parametro 'a' (ej. 11): ");
                read_mpz_from_input(b, "Ingrese el parametro 'b' (ej. 5): ");

                printf("\nSeleccione el destino de salida:\n");
                printf("  1. Mostrar en consola (CLI)\n");
                printf("  2. Guardar en archivo CSV\n");
                printf("  3. Mostrar en CLI y guardar en CSV\n");
                printf("Opcion de salida [1-3]: ");
                if (scanf("%d", &destino) != 1 || destino < 1 || destino > 3) {
                    printf("Opcion invalida.\n\n");
                    clear_input_buffer();
                    mpz_clears(p, a, b, NULL);
                    break;
                }
                clear_input_buffer();

                if (destino == 2 || destino == 3) {
                    printf("Ingrese nombre del archivo CSV [default: puntos_curva.csv]: ");
                    if (fgets(filename, sizeof(filename), stdin) == NULL || filename[0] == '\n') {
                        strcpy(filename, "puntos_curva.csv");
                    } else {
                        size_t fn_len = strlen(filename);
                        while (fn_len > 0 && (filename[fn_len - 1] == '\n' || filename[fn_len - 1] == '\r')) {
                            filename[--fn_len] = '\0';
                        }
                    }
                }

                size_t num_points = 0;
                point_t* points = elipar_rational_points(a, b, p, &num_points);

                if (points == NULL) {
                    printf("No se pudieron calcular los puntos (curva singular, p fuera de rango o error de memoria).\n\n");
                    mpz_clears(p, a, b, NULL);
                    break;
                }

                if (destino == 1 || destino == 3) {
                    printf("\n=====================================================\n");
                    gmp_printf(" PUNTOS RACIONALES: y^2 = x^3 + %Zdx + %Zd (mod %Zd)\n", a, b, p);
                    printf(" Coordenadas proyectivas (x, y, z) - Total: %zu puntos\n", num_points);
                    printf("=====================================================\n");
                    for (size_t i = 0; i < num_points; i++) {
                        if (point_is_infinity(&points[i])) {
                            gmp_printf("  Punto %4zu: (%Zd, %Zd, %Zd)  <- Punto al infinito (O)\n",
                                       i + 1, points[i].x, points[i].y, points[i].z);
                        } else {
                            gmp_printf("  Punto %4zu: (%Zd, %Zd, %Zd)\n",
                                       i + 1, points[i].x, points[i].y, points[i].z);
                        }
                    }
                    printf("\n");
                }

                if (destino == 2 || destino == 3) {
                    elipar_points_to_csv(filename, points, num_points, a, b, p);
                    printf("\n");
                }

                elipar_free_points(points, num_points);
                mpz_clears(p, a, b, NULL);
                break;
            }

            case 3: {
                printf("\n--- Ejercicio 2.1: Generar Curva Eliptica No-Singular en GF(p) ---\n");
                unsigned int n_bits = 0;
                printf("Ingrese la longitud en bits n (ej. 16, 32, 64, 512, 1024, 2048): ");
                if (scanf("%u", &n_bits) != 1 || n_bits < 3) {
                    printf("Longitud en bits invalida (debe ser >= 3).\n\n");
                    clear_input_buffer();
                    break;
                }
                clear_input_buffer();

                mpz_t p, a, b;
                mpz_inits(p, a, b, NULL);

                clock_t t0 = clock();
                if (elipar_generate_curve(p, a, b, n_bits, rng_state) == 0) {
                    clock_t t1 = clock();
                    double elapsed = (double)(t1 - t0) / CLOCKS_PER_SEC;

                    printf("\n>>> Curva no singular generada exitosamente en %.4f s <<<\n", elapsed);
                    gmp_printf("  Primo p (%u bits):\n    %Zd\n", (unsigned int)mpz_sizeinbase(p, 2), p);
                    gmp_printf("  Parametro a:\n    %Zd\n", a);
                    gmp_printf("  Parametro b:\n    %Zd\n", b);
                    printf("  Ecuacion: y^2 = x^3 + ax + b (mod p)\n");
                    printf("  Discriminante: 4a^3 + 27b^2 != 0 (mod p) [NO SINGULAR]\n\n");
                } else {
                    printf("Error al generar la curva.\n\n");
                }

                mpz_clears(p, a, b, NULL);
                break;
            }

            case 4: {
                printf("\n--- Ejercicio 2.2: Suma de Puntos P + Q (donde P != +-Q) ---\n");
                printf("(Puede ingresar expresiones en formato de potencias como 2^31 - 1 o 2^61 - 1)\n\n");

                mpz_t p, a, b;
                mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Ingrese el primo p (ej. 2^31 - 1 o 65537): ");
                read_mpz_from_input(a, "Ingrese el parametro 'a': ");
                read_mpz_from_input(b, "Ingrese el parametro 'b': ");

                if (elipar_is_singular(a, b, p)) {
                    printf("Advertencia: La curva es singular (4a^3 + 27b^2 = 0 mod p).\n");
                }

                point_t P, Q, R;
                point_init(&P); point_init(&Q); point_init(&R);

                input_point(&P, "P");
                input_point(&Q, "Q");

                printf("\n--- Verificando pertenencia a la curva --- \n");
                bool p_ok = elipar_is_point_on_curve(&P, a, b, p);
                bool q_ok = elipar_is_point_on_curve(&Q, a, b, p);
                printf("  P en curva: %s\n", p_ok ? "SI [VALIDO]" : "NO [ERROR]");
                printf("  Q en curva: %s\n", q_ok ? "SI [VALIDO]" : "NO [ERROR]");

                if (!p_ok || !q_ok) {
                    printf("Operacion cancelada: Uno o ambos puntos no pertenecen a la curva.\n\n");
                } else {
                    if (elipar_point_add(&R, &P, &Q, a, b, p) == 0) {
                        printf("\n>>> Resultado de la suma P + Q <<<\n");
                        point_print("  R = P + Q", &R);
                        printf("  R pertenece a la curva: %s\n\n",
                               elipar_is_point_on_curve(&R, a, b, p) ? "SI [CORRECTO]" : "NO");
                    } else {
                        printf("Error al calcular la suma de puntos.\n\n");
                    }
                }

                point_clear(&P); point_clear(&Q); point_clear(&R);
                mpz_clears(p, a, b, NULL);
                break;
            }

            case 5: {
                printf("\n--- Ejercicio 2.3: Duplicacion de Punto 2P ---\n");
                printf("(Puede ingresar expresiones en formato de potencias como 2^31 - 1 o 2^61 - 1)\n\n");

                mpz_t p, a, b;
                mpz_inits(p, a, b, NULL);
                read_mpz_from_input(p, "Ingrese el primo p (ej. 2^31 - 1 o 65537): ");
                read_mpz_from_input(a, "Ingrese el parametro 'a': ");
                read_mpz_from_input(b, "Ingrese el parametro 'b': ");

                point_t P, R;
                point_init(&P); point_init(&R);

                input_point(&P, "P");

                printf("\n--- Verificando pertenencia a la curva --- \n");
                bool p_ok = elipar_is_point_on_curve(&P, a, b, p);
                printf("  P en curva: %s\n", p_ok ? "SI [VALIDO]" : "NO [ERROR]");

                if (!p_ok) {
                    printf("Operacion cancelada: El punto P no pertenece a la curva.\n\n");
                } else {
                    if (elipar_point_double(&R, &P, a, b, p) == 0) {
                        printf("\n>>> Resultado de la duplicacion 2P <<<\n");
                        point_print("  R = 2P", &R);
                        printf("  R pertenece a la curva: %s\n\n",
                               elipar_is_point_on_curve(&R, a, b, p) ? "SI [CORRECTO]" : "NO");
                    } else {
                        printf("Error al calcular la duplicacion de punto.\n\n");
                    }
                }

                point_clear(&P); point_clear(&R);
                mpz_clears(p, a, b, NULL);
                break;
            }

            case 6: {
                elipar_run_section3_question2();
                break;
            }

            case 7: {
                elipar_run_section3_question3();
                break;
            }

            case 8: {
                printf("\nSaliendo del programa. ¡Hasta luego!\n\n");
                break;
            }

            default:
                printf("\n[!] Opcion no valida. Seleccione una opcion del 1 al 8.\n\n");
                break;
        }

    } while (opcion != 8);

    gmp_randclear(rng_state);
    return 0;
}
