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
    int fin;
} point_t;


int elipar_quadratic_residue(int** qr, const int p);
int elipar_rational_points(point_t* points , const int a, const int b, const int p);

static int elipar_is_in(const int a, const size_t len ,const int* arr);


#endif