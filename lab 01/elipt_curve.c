#include "elipt_curve.h"
#include <stddef.h>


qr_table_t* elipar_quadratic_residue(const int p) {
    if (p <= 3) {
        fprintf(stderr, "Error(quad): Numero invalido, debe ser mayor a 3.\n");
        return NULL;
    }

    qr_table_t* table = (qr_table_t*)malloc(sizeof(qr_table_t));
    if (table == NULL) {
        perror("Error(quad): Error al asignar memoria a la tabla hash");
        return NULL;
    }

    table->capacity = (size_t)p;
    table->count = 0;
    table->p = p;
    table->entries = (qr_entry_t*)calloc(table->capacity, sizeof(qr_entry_t));
    if (table->entries == NULL) {
        perror("Error(quad): Error al asignar memoria a las entradas de la tabla");
        free(table);
        return NULL;
    }

    printf("=== Residuos cuadraticos y sus raices modulo %d ===\n", p);

    /*
     * Eficiencia:
     * Para cualquier primo p > 3, existen (p - 1)/2 residuos cuadráticos no nulos
     * más el 0, totalizando ((p - 1)/2) + 1 residuos cuadráticos.
     *
     * Iterando y desde 0 hasta (p - 1)/2:
     * - y = 0  => r = 0, raiz = 0
     * - y > 0  => r = y^2 mod p, raices = {y, p - y}
     * Cada iteracion genera un residuo cuadratico unico sin colisiones en O(p).
     */
    size_t limit = (size_t)((p - 1) / 2);
    for (size_t y = 0; y <= limit; y++) {
        int r = (int)(((long long)y * y) % p);

        qr_entry_t* entry = &table->entries[r];
        entry->key = r;
        entry->is_occupied = true;

        if (y == 0) {
            entry->roots[0] = 0;
            entry->roots[1] = 0;
            entry->root_count = 1;
            printf("Residuo cuadratico: %-5d | Raices: { %d }\n", r, entry->roots[0]);
        } else {
            entry->roots[0] = (int)y;
            entry->roots[1] = p - (int)y;
            entry->root_count = 2;
            printf("Residuo cuadratico: %-5d | Raices: { %d, %d }\n", r, entry->roots[0], entry->roots[1]);
        }
        table->count++;
    }

    printf("Total de residuos cuadraticos encontrados: %zu\n\n", table->count);
    return table;
}

const qr_entry_t* elipar_qr_lookup(const qr_table_t* table, const int residue) {
    if (table == NULL || table->entries == NULL || table->p <= 0) {
        return NULL;
    }
    int norm = ((residue % table->p) + table->p) % table->p;
    if (table->entries[norm].is_occupied) {
        return &table->entries[norm];
    }
    return NULL;
}

void elipar_qr_free(qr_table_t* table) {
    if (table != NULL) {
        if (table->entries != NULL) {
            free(table->entries);
            table->entries = NULL;
        }
        free(table);
    }
}

point_t* elipar_rational_points(const int a, const int b, const int p, size_t* num_points) {
    if (num_points != NULL) {
        *num_points = 0;
    }

    if (p <= 3) {
        fprintf(stderr, "Error(rati): Numero invalido, p debe ser mayor a 3.\n");
        return NULL;
    }

    /* Normalizacion de parametros a y b modulo p */
    int tmp_a = ((a % p) + p) % p;
    int tmp_b = ((b % p) + p) % p;

    /*
     * Validacion de no-singularidad por medio del discriminante discreto:
     * Delta = 4a^3 + 27b^2 != 0 (mod p)
     */
    long long a3 = ((long long)tmp_a * tmp_a % p) * tmp_a % p;
    long long b2 = (long long)tmp_b * tmp_b % p;
    long long discri = (4LL * a3 + 27LL * b2) % p;
    discri = (discri + p) % p;

    if (discri == 0) {
        fprintf(stderr, "Error(rati): Curva eliptica singular (4a^3 + 27b^2 = 0 mod %d).\n", p);
        return NULL;
    }

    /* Obtener la tabla hash de residuos cuadraticos con sus raices */
    qr_table_t* qr_table = elipar_quadratic_residue(p);
    if (qr_table == NULL) {
        return NULL;
    }

    /*
     * Como maximo, cada x en [0, p-1] tiene 2 valores de y asociados,
     * mas 1 punto al infinito O = (0, 1, 0). Capacidad maxima inicial: 2p + 1.
     */
    point_t* points = (point_t*)malloc(sizeof(point_t) * (2 * (size_t)p + 1));
    if (points == NULL) {
        perror("Error(rati): Error al asignar memoria para los puntos racionales");
        elipar_qr_free(qr_table);
        return NULL;
    }

    size_t count = 0;

    /*
     * 1. Punto al infinito en coordenadas proyectivas: (0, 1, 0)
     */
    points[count].x = 0;
    points[count].y = 1;
    points[count].z = 0;
    count++;

    /*
     * 2. Puntos afines (x, y, 1):
     * Para cada x in {0, ..., p - 1}, evaluamos rhs = x^3 + ax + b (mod p).
     * Si rhs es residuo cuadratico en qr_table, recuperamos sus raices y en O(1).
     */
    for (int x = 0; x < p; x++) {
        long long x_ll = (long long)x;
        long long x3 = (x_ll * x_ll % p) * x_ll % p;
        long long ax_val = (long long)tmp_a * x_ll % p;
        long long rhs = (x3 + ax_val + tmp_b) % p;
        rhs = (rhs + p) % p;

        const qr_entry_t* entry = elipar_qr_lookup(qr_table, (int)rhs);
        if (entry != NULL) {
            for (int k = 0; k < entry->root_count; k++) {
                points[count].x = x;
                points[count].y = entry->roots[k];
                points[count].z = 1;
                count++;
            }
        }
    }

    /* Ya no necesitamos la tabla hash */
    elipar_qr_free(qr_table);

    /* Ajustamos el tamano del arreglo a la cantidad exacta de puntos */
    point_t* resized = (point_t*)realloc(points, sizeof(point_t) * count);
    if (resized != NULL) {
        points = resized;
    }

    if (num_points != NULL) {
        *num_points = count;
    }

    printf("Total de puntos racionales encontrados (incluyendo punto al infinito): %zu\n\n", count);
    return points;
}

point_t* elipar_rational(const int a, const int b, const int p, size_t* num_points) {
    return elipar_rational_points(a, b, p, num_points);
}

size_t elipar_count_rational_points(const int a, const int b, const int p) {
    size_t count = 0;
    point_t* pts = elipar_rational_points(a, b, p, &count);
    if (pts != NULL) {
        free(pts);
    }
    return count;
}

int elipar_points_to_csv(const char* filename, const point_t* points, const size_t num_points, const int a, const int b, const int p) {
    if (filename == NULL || points == NULL) {
        fprintf(stderr, "Error(csv): Parametros invalidos para exportar a CSV.\n");
        return 1;
    }

    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error(csv): No se pudo abrir el archivo CSV para escritura");
        return 1;
    }

    /*
     * Formato requerido para el CSV:
     * Linea 1: vacio, 'p', valor de p
     * Linea 2: vacio, 'a', valor de a
     * Linea 3: vacio, 'b', valor de b
     * Linea 4: vacio, 'count', y la cantidad de puntos
     * Linea 5: encabezado de columnas x,y,z
     * Lineas siguientes: coordenadas x,y,z de cada punto
     */
    fprintf(file, ",p,%d\n", p);
    fprintf(file, ",a,%d\n", a);
    fprintf(file, ",b,%d\n", b);
    fprintf(file, ",count,%zu\n", num_points);
    fprintf(file, "x,y,z\n");

    for (size_t i = 0; i < num_points; i++) {
        fprintf(file, "%d,%d,%d\n", points[i].x, points[i].y, points[i].z);
    }

    fclose(file);
    printf("Puntos racionales exportados exitosamente a '%s' (%zu puntos en total).\n", filename, num_points);
    return 0;
}

int elipar_is_in(const int a, const size_t len, const int* arr) {
    if (arr == NULL) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        if (arr[i] == a) {
            return (int)i;
        }
    }
    return -1;
}