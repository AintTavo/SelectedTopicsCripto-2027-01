#ifndef ELIPT_CURVE_H
#define ELIPT_CURVE_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <math.h>

typedef struct {
    int x;
    int y;
    int z; /* Coordenadas proyectivas: z = 1 (punto normal), (0, 1, 0) punto al infinito */
} point_t;


/* Entrada del diccionario / tabla hash de residuos cuadraticos */
typedef struct qr_entry {
    int key;            /* Residuo cuadratico (etiqueta) */
    int roots[2];       /* Raices cuadradas asociadas */
    int root_count;     /* Cantidad de raices asociadas (1 para 0, 2 para r > 0) */
    bool is_occupied;   /* Indica si la cubeta contiene un residuo */
} qr_entry_t;

/* Estructura del diccionario / tabla hash */
typedef struct qr_table {
    qr_entry_t* entries; /* Cubetas indexadas por residuo modulo p */
    size_t capacity;     /* Capacidad de la tabla (modulo p) */
    size_t count;        /* Numero de residuos cuadraticos almacenados */
    int p;               /* Modulo primo */
} qr_table_t;

typedef qr_table_t qr_dict_t;

/* Funciones para residuos cuadraticos (diccionario / tabla hash) */
qr_table_t* elipar_quadratic_residue(const int p);
const qr_entry_t* elipar_qr_lookup(const qr_table_t* table, const int residue);
void elipar_qr_free(qr_table_t* table);

/* Funciones para puntos racionales en coordenadas proyectivas */
point_t* elipar_rational_points(const int a, const int b, const int p, size_t* num_points);
point_t* elipar_rational(const int a, const int b, const int p, size_t* num_points);
size_t elipar_count_rational_points(const int a, const int b, const int p);

/* Exportar puntos a archivo CSV con metadatos de curva y conteo */
int elipar_points_to_csv(const char* filename, const point_t* points, const size_t num_points, const int a, const int b, const int p);

int elipar_is_in(const int a, const size_t len ,const int* arr);


#endif