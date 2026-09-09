#include "elipt_curve.h"

static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

int main(void) {
    int opcion = 0;

    do {
        printf("=====================================================\n");
        printf("     LABORATORIO 01: CURVAS ELIPTICAS Y RESIDUOS     \n");
        printf("=====================================================\n");
        printf("1. Calcular residuos cuadraticos y raices modulo p\n");
        printf("2. Calcular puntos racionales de curva eliptica\n");
        printf("3. Salir\n");
        printf("Seleccione una opcion [1-3]: ");

        if (scanf("%d", &opcion) != 1) {
            printf("\nEntrada no valida. Intente de nuevo.\n\n");
            clear_input_buffer();
            continue;
        }

        switch (opcion) {
            case 1: {
                int p = 0;
                printf("\n--- Residuos Cuadraticos y Raices ---\n");
                printf("Ingrese el numero primo p (p > 3): ");
                if (scanf("%d", &p) != 1) {
                    printf("Entrada no valida.\n\n");
                    clear_input_buffer();
                    break;
                }

                if (p <= 3) {
                    printf("Error: p debe ser mayor a 3.\n\n");
                    break;
                }

                qr_table_t* table = elipar_quadratic_residue(p);
                if (table != NULL) {
                    elipar_qr_free(table);
                }
                break;
            }

            case 2: {
                int p = 0, a = 0, b = 0;
                int destino = 0;
                char filename[256];

                printf("\n--- Puntos Racionales de Curva Eliptica: y^2 = x^3 + ax + b (mod p) ---\n");
                printf("Ingrese el numero primo p (p > 3): ");
                if (scanf("%d", &p) != 1) {
                    printf("Entrada no valida.\n\n");
                    clear_input_buffer();
                    break;
                }

                if (p <= 3) {
                    printf("Error: p debe ser mayor a 3.\n\n");
                    break;
                }

                printf("Ingrese el parametro 'a': ");
                if (scanf("%d", &a) != 1) {
                    printf("Entrada no valida.\n\n");
                    clear_input_buffer();
                    break;
                }

                printf("Ingrese el parametro 'b': ");
                if (scanf("%d", &b) != 1) {
                    printf("Entrada no valida.\n\n");
                    clear_input_buffer();
                    break;
                }

                printf("\nSeleccione el destino de salida:\n");
                printf("  1. Mostrar en consola (CLI)\n");
                printf("  2. Guardar en archivo CSV\n");
                printf("  3. Mostrar en CLI y guardar en CSV\n");
                printf("Opcion de salida [1-3]: ");
                if (scanf("%d", &destino) != 1 || destino < 1 || destino > 3) {
                    printf("Opcion invalida.\n\n");
                    clear_input_buffer();
                    break;
                }

                if (destino == 2 || destino == 3) {
                    printf("Ingrese el nombre del archivo CSV (ej. puntos.csv): ");
                    if (scanf("%255s", filename) != 1) {
                        strcpy(filename, "puntos_curva.csv");
                    }
                }

                size_t num_points = 0;
                point_t* points = elipar_rational_points(a, b, p, &num_points);

                if (points == NULL) {
                    printf("No se pudieron calcular los puntos (curva singular o parametros invalidos).\n\n");
                    break;
                }

                /* Salida en CLI */
                if (destino == 1 || destino == 3) {
                    printf("\n=====================================================\n");
                    printf(" PUNTOS RACIONALES: y^2 = x^3 + %dx + %d (mod %d)\n", a, b, p);
                    printf(" Coordenadas proyectivas (x, y, z) - Total: %zu puntos\n", num_points);
                    printf("=====================================================\n");
                    for (size_t i = 0; i < num_points; i++) {
                        if (points[i].z == 0) {
                            printf("  Punto %3zu: (%3d, %3d, %3d)  <- Punto al infinito (O)\n",
                                   i + 1, points[i].x, points[i].y, points[i].z);
                        } else {
                            printf("  Punto %3zu: (%3d, %3d, %3d)\n",
                                   i + 1, points[i].x, points[i].y, points[i].z);
                        }
                    }
                    printf("\n");
                }

                /* Salida en archivo CSV */
                if (destino == 2 || destino == 3) {
                    elipar_points_to_csv(filename, points, num_points, a, b, p);
                    printf("\n");
                }

                free(points);
                break;
            }

            case 3:
                printf("\nSaliendo del programa. Hasta luego!\n\n");
                break;

            default:
                printf("\nOpcion no valida. Seleccione 1, 2 o 3.\n\n");
                break;
        }

    } while (opcion != 3);

    return 0;
}
