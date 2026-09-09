#include "elipt_curve.h"
#include <stddef.h>


int elipar_quadratic_residue(int** qr, const int p){
    if ( p < 3 ) {
        perror("Error(quad): Número inválido, debe ser mayor a 3");
        return 1;
    }
    
    size_t len_qr = (( p - 1 ) / 2) + 1;
    size_t j = 0;
    *qr = (int*) malloc(sizeof(int) * len_qr );
    if ( *qr == NULL ) {
        perror("Error(quad) : Error al asignar memoria a qr");
        return 1;
    }
    
    for ( size_t i = 0 ; i < len_qr ; i++ ) {
        *qr[i] = (int)(i * i) % p;  
    }
    
    return len_qr;
}

int elipar_rational_points(point_t* points ,const int a, const int b, const int p){
    if ( p < 3 ) {
        perror("Error(quad): Número inválido, debe ser mayor a 3");
    }
    
    int tmp_a, tmp_b;
    if ( a > p || a < 0 )
        tmp_a = (( a % p ) + p ) % p;
    if ( b > p || b < 0 )
        tmp_b = (( b % p ) + p ) % p;

    int discri;
    discri = (int)((4 * pow(a, 3)) + ( 27 * pow(b, 2))) % p;
    if ( discri == 0 ) {
        perror("Error(rati): Curva eliptica no singular");
        return 1;
    }

    points = (points*)malloc(sizeof(points));
    
    int* tmp_qr;
    elipar_quadratic_residue( &tmp_qr, p);
    for ( size_t i = 0 ; i < p ; i++ ){
        int tmp_res = (((int)( pow( i, 3) + (i * a) + b ) % p ) + p ) % p;
        if (elipar_is_in(tmp_res, ((p - 1)/2) + 1, tmp_qr )){
            
        }
            
    }
    
    return 0;
}


static int elipar_is_in(const int a, const size_t len ,const int* arr) {
    for ( size_t i = 0 ; i < len ; i ++ ) {
        if ( arr[i] == a ) {
            return i;
        }
    }
    return -1;
}