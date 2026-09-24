#include "ecdsa.h"
#include "ellipticcurve/elipt_curve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <gmp.h>

static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

/* Entrada de punto: en la interfaz de usuario se manejan unicamente pares de coordenadas (x, y) */
static void input_point(point_t* pt, const char* name) {
    char buf[128];
    printf("\n  -- Coordenadas del punto %s --\n", name);
    printf("  ¿Es el punto al infinito O? (s/n) [default: n]: ");
    if (fgets(buf, sizeof(buf), stdin) != NULL &&
        (buf[0] == 's' || buf[0] == 'S' || buf[0] == 'y' || buf[0] == 'Y')) {
        point_set_infinity(pt);
        printf("  -> %s definido como punto al infinito.\n", name);
        return;
    }

    char prompt_x[128], prompt_y[128];
    snprintf(prompt_x, sizeof(prompt_x), "  Ingrese coordenada x de %s: ", name);
    read_mpz_from_input(pt->x, prompt_x);

    snprintf(prompt_y, sizeof(prompt_y), "  Ingrese coordenada y de %s: ", name);
    read_mpz_from_input(pt->y, prompt_y);

    /* En coordenadas proyectivas internas se fija Z = 1 */
    mpz_set_ui(pt->z, 1);
}

/* Generador de Hash basico para firmas: convierte mensaje ASCII a entero mod q */
static void hash_message(mpz_t rop, const char* msg, const mpz_t q) {
    mpz_set_ui(rop, 0);
    for (size_t i = 0; msg[i] != '\0'; i++) {
        mpz_mul_ui(rop, rop, 256);
        mpz_add_ui(rop, rop, (unsigned char)msg[i]);
        mpz_mod(rop, rop, q);
    }
}

/* Carga parametros estandar de secp256k1 */
static void load_curve_secp256k1(mpz_t p, mpz_t a, mpz_t b, mpz_t q, point_t* G) {
    mpz_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_set_ui(a, 0);
    mpz_set_ui(b, 7);
    mpz_set_str(q, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    mpz_set_str(G->x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_set_str(G->y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    mpz_set_ui(G->z, 1);
}

/* Carga parametros de una curva pequeña para pruebas didacticas (p = 97) */
static void load_curve_toy(mpz_t p, mpz_t a, mpz_t b, mpz_t q, point_t* G) {
    mpz_set_ui(p, 97);
    mpz_set_ui(a, 2);
    mpz_set_ui(b, 3);
    mpz_set_ui(q, 5); /* Subgrupo de orden 5 con G = (3, 6) */
    mpz_set_ui(G->x, 3);
    mpz_set_ui(G->y, 6);
    mpz_set_ui(G->z, 1);
}

/* Seleccion o entrada interactiva de los parametros de la curva */
static int choose_or_input_curve(mpz_t p, mpz_t a, mpz_t b, mpz_t q, point_t* G) {
    printf("\nSeleccione el origen de los parametros de la curva:\n");
    printf("  1. Curva estandar secp256k1 (Criptografica - 256 bits)\n");
    printf("  2. Curva pequeña de prueba (p = 97, G = (3, 6))\n");
    printf("  3. Ingresar parametros manualmente\n");
    printf("Seleccion [1-3] [default: 1]: ");

    char line[128];
    int choice = 1;
    if (fgets(line, sizeof(line), stdin) != NULL && line[0] != '\n') {
        sscanf(line, "%d", &choice);
    }

    if (choice == 1) {
        load_curve_secp256k1(p, a, b, q, G);
        printf("[+] Curva secp256k1 cargada exitosamente.\n");
        return 0;
    } else if (choice == 2) {
        load_curve_toy(p, a, b, q, G);
        printf("[+] Curva reducida (p=97) cargada exitosamente.\n");
        return 0;
    } else {
        read_mpz_from_input(p, "Primo p de la curva: ");
        read_mpz_from_input(a, "Parametro a: ");
        read_mpz_from_input(b, "Parametro b: ");

        if (mpz_cmp_ui(p, 200000) <= 0) {
            printf("[*] El primo p es pequeño (<= 200,000). Calculando cardinalidad automaticamente...\n");
            size_t count = 0;
            point_t* pts = elipar_rational_points(a, b, p, &count);
            if (pts != NULL && count > 1) {
                mpz_set_ui(q, count);
                size_t g_idx = 1;
                for (size_t i = 0; i < count; i++) {
                    if (!point_is_infinity(&pts[i])) { g_idx = i; break; }
                }
                point_set(G, &pts[g_idx]);
                gmp_printf(" => Cardinalidad total calculada: %Zd\n", q);
                gmp_printf(" => Punto Generador (G) seleccionado: (%Zd, %Zd)\n", G->x, G->y);
                elipar_free_points(pts, count);
            } else {
                printf("[-] Error calculando puntos. Ingrese orden manualmente:\n");
                read_mpz_from_input(q, "Orden q del generador: ");
                input_point(G, "Generador G");
            }
        } else {
            read_mpz_from_input(q, "Orden q del generador: ");
            input_point(G, "Generador G");
        }
        return 0;
    }
}

/* Guardar claves en archivos de texto: z = 1 para puntos afines normales, o x=0, y=1, z=0 para el punto al infinito */
static int save_keys_to_files(const keys_t* keys, const char* pub_file, const char* priv_file) {
    FILE* fpub = fopen(pub_file, "w");
    if (!fpub) return -1;
    gmp_fprintf(fpub, "p=%Zd\na=%Zd\nb=%Zd\nq=%Zd\n",
                keys->keys_pub.kpub_p, keys->keys_pub.kpub_a,
                keys->keys_pub.kpub_b, keys->keys_pub.kpub_q);

    /* Generador A: z = 1 si es punto normal, x = 0, y = 1, z = 0 si es punto al infinito */
    if (point_is_infinity(&keys->keys_pub.kpub_A)) {
        gmp_fprintf(fpub, "Ax=0\nAy=1\nAz=0\n");
    } else {
        point_t A_aff; point_init(&A_aff);
        elipar_projective_to_affine(&A_aff, &keys->keys_pub.kpub_A, keys->keys_pub.kpub_p);
        gmp_fprintf(fpub, "Ax=%Zd\nAy=%Zd\nAz=1\n", A_aff.x, A_aff.y);
        point_clear(&A_aff);
    }

    /* Llave publica B: z = 1 si es punto normal, x = 0, y = 1, z = 0 si es punto al infinito */
    if (point_is_infinity(&keys->keys_pub.kpub_B)) {
        gmp_fprintf(fpub, "Bx=0\nBy=1\nBz=0\n");
    } else {
        point_t B_aff; point_init(&B_aff);
        elipar_projective_to_affine(&B_aff, &keys->keys_pub.kpub_B, keys->keys_pub.kpub_p);
        gmp_fprintf(fpub, "Bx=%Zd\nBy=%Zd\nBz=1\n", B_aff.x, B_aff.y);
        point_clear(&B_aff);
    }
    fclose(fpub);

    FILE* fpriv = fopen(priv_file, "w");
    if (!fpriv) return -1;
    gmp_fprintf(fpriv, "d=%Zd\n", keys->keys_priv.kpriv_d);
    fclose(fpriv);

    return 0;
}

/* Guardar firma en archivo de texto */
static int save_signature_to_file(const char* file, const char* msg, const mpz_t hx, const ecdsa_sign_t* sig) {
    FILE* f = fopen(file, "w");
    if (!f) return -1;
    fprintf(f, "Mensaje: %s\n", msg);
    gmp_fprintf(f, "e=%Zd\nr=%Zd\ns=%Zd\n", hx, sig->sign_r, sig->sign_s);
    fclose(f);
    return 0;
}

/* Cargar clave publica desde archivo: soporta coordenadas afines (x, y, 1) y punto al infinito (0, 1, 0) */
static int load_public_key_from_file(kpub_t* pub, const char* file) {
    FILE* f = fopen(file, "r");
    if (!f) return -1;

    char line[512];
    int loaded = 0;
    bool has_az = false, has_bz = false;

    while (fgets(line, sizeof(line), f)) {
        char key[64], val[448];
        if (sscanf(line, "%63[^=]=%447s", key, val) == 2) {
            if (strcmp(key, "p") == 0) { mpz_set_str(pub->kpub_p, val, 0); loaded++; }
            else if (strcmp(key, "a") == 0) { mpz_set_str(pub->kpub_a, val, 0); loaded++; }
            else if (strcmp(key, "b") == 0) { mpz_set_str(pub->kpub_b, val, 0); loaded++; }
            else if (strcmp(key, "q") == 0 || strcmp(key, "n") == 0) { mpz_set_str(pub->kpub_q, val, 0); loaded++; }
            else if (strcmp(key, "Ax") == 0 || strcmp(key, "Gx") == 0) { mpz_set_str(pub->kpub_A.x, val, 0); loaded++; }
            else if (strcmp(key, "Ay") == 0 || strcmp(key, "Gy") == 0) { mpz_set_str(pub->kpub_A.y, val, 0); loaded++; }
            else if (strcmp(key, "Az") == 0 || strcmp(key, "Gz") == 0) { mpz_set_str(pub->kpub_A.z, val, 0); has_az = true; }
            else if (strcmp(key, "Bx") == 0 || strcmp(key, "Qx") == 0) { mpz_set_str(pub->kpub_B.x, val, 0); loaded++; }
            else if (strcmp(key, "By") == 0 || strcmp(key, "Qy") == 0) { mpz_set_str(pub->kpub_B.y, val, 0); loaded++; }
            else if (strcmp(key, "Bz") == 0 || strcmp(key, "Qz") == 0) { mpz_set_str(pub->kpub_B.z, val, 0); has_bz = true; }
        }
    }
    fclose(f);

    if (!has_az) mpz_set_ui(pub->kpub_A.z, 1);
    if (!has_bz) mpz_set_ui(pub->kpub_B.z, 1);

    if (mpz_cmp_ui(pub->kpub_A.z, 0) == 0) {
        point_set_infinity(&pub->kpub_A);
    } else if (mpz_cmp_ui(pub->kpub_A.z, 1) != 0) {
        point_t aff; point_init(&aff);
        elipar_projective_to_affine(&aff, &pub->kpub_A, pub->kpub_p);
        point_set(&pub->kpub_A, &aff);
        point_clear(&aff);
    }

    if (mpz_cmp_ui(pub->kpub_B.z, 0) == 0) {
        point_set_infinity(&pub->kpub_B);
    } else if (mpz_cmp_ui(pub->kpub_B.z, 1) != 0) {
        point_t aff; point_init(&aff);
        elipar_projective_to_affine(&aff, &pub->kpub_B, pub->kpub_p);
        point_set(&pub->kpub_B, &aff);
        point_clear(&aff);
    }

    return (loaded >= 6) ? 0 : -1;
}

/* Cargar clave privada desde archivo */
static int load_private_key_from_file(kpriv_t* priv, const char* file) {
    FILE* f = fopen(file, "r");
    if (!f) return -1;

    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        char key[64], val[448];
        if (sscanf(line, "%63[^=]=%447s", key, val) == 2) {
            if (strcmp(key, "d") == 0) {
                mpz_set_str(priv->kpriv_d, val, 0);
                loaded = 1;
                break;
            }
        }
    }
    fclose(f);
    return (loaded == 1) ? 0 : -1;
}

/* Cargar firma desde archivo */
static int load_signature_from_file(const char* file, char* msg_buf, size_t msg_sz, mpz_t hx, ecdsa_sign_t* sig) {
    FILE* f = fopen(file, "r");
    if (!f) return -1;

    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Mensaje: ", 9) == 0 && msg_buf) {
            strncpy(msg_buf, line + 9, msg_sz - 1);
            msg_buf[msg_sz - 1] = '\0';
            size_t len = strlen(msg_buf);
            if (len > 0 && (msg_buf[len - 1] == '\n' || msg_buf[len - 1] == '\r')) msg_buf[len - 1] = '\0';
        } else {
            char key[64], val[448];
            if (sscanf(line, "%63[^=]=%447s", key, val) == 2) {
                if (strcmp(key, "e") == 0 || strcmp(key, "hx") == 0) { mpz_set_str(hx, val, 0); loaded++; }
                else if (strcmp(key, "r") == 0) { mpz_set_str(sig->sign_r, val, 0); loaded++; }
                else if (strcmp(key, "s") == 0) { mpz_set_str(sig->sign_s, val, 0); loaded++; }
            }
        }
    }
    fclose(f);
    return (loaded >= 3) ? 0 : -1;
}

/* =========================================================================
 * PROGRAMA PRINCIPAL: INTERFAZ VISUAL DEDICADA A LA SECCION 2 (ECDSA)
 * ========================================================================= */
int main(void) {
    int opcion = 0;
    gmp_randstate_t rng_state;
    gmp_randinit_default(rng_state);
    gmp_randseed_ui(rng_state, (unsigned long)time(NULL));

    /* Variables de sesion para compartir claves y firmas en memoria */
    keys_t session_keys;
    bool has_session_keys = false;

    ecdsa_sign_t session_sig;
    mpz_t session_hx;
    mpz_init(session_hx);
    char session_msg[512] = {0};
    bool has_session_sig = false;

    do {
        printf("======================================================================\n");
        printf("       LABORATORIO 03: ECDSA Y CRIPTOGRAFIA DE CURVAS ELIPTICAS      \n");
        printf("======================================================================\n");
        printf("--- SECCION 2: PROTOCOLO ECDSA (ESTRUCTURAS LAB 03) ---\n");
        printf("  1. Generar Llaves ECDSA (ecdsa_key_gen -> guarda txt)\n");
        printf("  2. Firmar Mensaje ECDSA (ecdsa_signature -> guarda txt)\n");
        printf("  3. Verificar Firma ECDSA (ecdsa_sign_verification)\n");
        printf("\n  4. Salir\n");
        printf("======================================================================\n");
        printf("Seleccione una opcion [1-4]: ");

        if (scanf("%d", &opcion) != 1) {
            printf("\n[!] Entrada no valida. Intente de nuevo.\n\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (opcion) {
            case 1: {
                printf("\n--- Generar Llaves ECDSA (ecdsa_key_gen) ---\n");
                mpz_t p, a, b, q;
                mpz_inits(p, a, b, q, NULL);
                point_t G; point_init(&G);

                choose_or_input_curve(p, a, b, q, &G);

                if (has_session_keys) {
                    ecdsa_keys_clear(&session_keys);
                    has_session_keys = false;
                }

                printf("\n[*] Generando par de llaves con ecdsa_key_gen...\n");
                if (ecdsa_key_gen(&session_keys, p, a, b, G, q) == 0) {
                    has_session_keys = true;

                    /* En la interfaz de usuario se muestran unicamente pares de coordenadas (x, y) */
                    point_t G_pair, B_pair;
                    point_init(&G_pair);
                    point_init(&B_pair);
                    elipar_projective_to_affine(&G_pair, &session_keys.keys_pub.kpub_A, p);
                    elipar_projective_to_affine(&B_pair, &session_keys.keys_pub.kpub_B, p);

                    printf("\n=====================================================\n");
                    printf("        PAR DE LLAVES ECDSA GENERADO EXITOSAMENTE    \n");
                    printf("=====================================================\n");
                    gmp_printf("  Llave Privada (d):\n    %Zd\n\n", session_keys.keys_priv.kpriv_d);
                    gmp_printf("  Punto Generador G = A:\n    (x, y) = (%Zd, %Zd)\n\n",
                               G_pair.x, G_pair.y);
                    gmp_printf("  Llave Publica Q = B = d*G:\n    (x, y) = (%Zd, %Zd)\n",
                               B_pair.x, B_pair.y);
                    printf("=====================================================\n");

                    point_clear(&G_pair);
                    point_clear(&B_pair);

                    if (save_keys_to_files(&session_keys, "public_key.txt", "private_key.txt") == 0) {
                        printf("[+] Parametros y Clave Publica guardados en 'public_key.txt'\n");
                        printf("[+] Clave Privada guardada en 'private_key.txt'\n");
                    } else {
                        printf("[-] Advertencia: No se pudieron guardar los archivos de clave.\n");
                    }
                    printf("[*] Llaves almacenadas en memoria de sesion para firma y verificacion.\n\n");
                } else {
                    printf("[-] Error al generar las llaves.\n\n");
                }

                point_clear(&G);
                mpz_clears(p, a, b, q, NULL);
                break;
            }

            case 2: {
                printf("\n--- Firmar Mensaje ECDSA (ecdsa_signature) ---\n");
                mpz_t p, a, b, q;
                mpz_inits(p, a, b, q, NULL);
                point_t G; point_init(&G);
                kpriv_t priv; ecdsa_kpriv_init(&priv);

                bool use_session = false;
                if (has_session_keys) {
                    char ans[32];
                    printf("¿Desea usar las llaves generadas en la sesion actual? (s/n) [default: s]: ");
                    if (fgets(ans, sizeof(ans), stdin) == NULL || ans[0] == '\n' ||
                        ans[0] == 's' || ans[0] == 'S' || ans[0] == 'y' || ans[0] == 'Y') {
                        use_session = true;
                    }
                }

                if (use_session) {
                    mpz_set(p, session_keys.keys_pub.kpub_p);
                    mpz_set(a, session_keys.keys_pub.kpub_a);
                    mpz_set(b, session_keys.keys_pub.kpub_b);
                    mpz_set(q, session_keys.keys_pub.kpub_q);
                    point_set(&G, &session_keys.keys_pub.kpub_A);
                    mpz_set(priv.kpriv_d, session_keys.keys_priv.kpriv_d);
                    printf("[+] Usando llaves de sesion.\n");
                } else {
                    printf("\nOrigen de las llaves:\n");
                    printf("  1. Cargar desde archivos ('public_key.txt' y 'private_key.txt')\n");
                    printf("  2. Ingresar manualmente parametros y clave privada\n");
                    printf("Seleccion [1-2] [default: 1]: ");
                    char line[32];
                    int opt_keys = 1;
                    if (fgets(line, sizeof(line), stdin) != NULL && line[0] != '\n') {
                        sscanf(line, "%d", &opt_keys);
                    }

                    if (opt_keys == 1) {
                        kpub_t temp_pub; ecdsa_kpub_init(&temp_pub);
                        if (load_public_key_from_file(&temp_pub, "public_key.txt") == 0 &&
                            load_private_key_from_file(&priv, "private_key.txt") == 0) {
                            mpz_set(p, temp_pub.kpub_p);
                            mpz_set(a, temp_pub.kpub_a);
                            mpz_set(b, temp_pub.kpub_b);
                            mpz_set(q, temp_pub.kpub_q);
                            point_set(&G, &temp_pub.kpub_A);
                            printf("[+] Claves cargadas exitosamente de archivos.\n");
                            ecdsa_kpub_clear(&temp_pub);
                        } else {
                            printf("[-] No se pudieron leer los archivos. Proceda manualmente.\n");
                            ecdsa_kpub_clear(&temp_pub);
                            choose_or_input_curve(p, a, b, q, &G);
                            read_mpz_from_input(priv.kpriv_d, "Llave Privada d: ");
                        }
                    } else {
                        choose_or_input_curve(p, a, b, q, &G);
                        read_mpz_from_input(priv.kpriv_d, "Llave Privada d: ");
                    }
                }

                char msg[512] = {0};
                mpz_t hx; mpz_init(hx);

                printf("\nSeleccione el modo del mensaje a enviar/firmar:\n");
                printf("  1. Mensaje como un numero directamente (e = valor numerico)\n");
                printf("  2. Ingresar texto del mensaje y hashearlo (Toy Hash mod q)\n");
                printf("Seleccion [1-2] [default: 1]: ");
                char mopt[32];
                int msg_opt = 1;
                if (fgets(mopt, sizeof(mopt), stdin) != NULL && mopt[0] != '\n') {
                    sscanf(mopt, "%d", &msg_opt);
                }

                if (msg_opt == 2) {
                    printf("\nIngrese el mensaje de texto a firmar: ");
                    if (fgets(msg, sizeof(msg), stdin) != NULL) {
                        size_t len = strlen(msg);
                        if (len > 0 && (msg[len - 1] == '\n' || msg[len - 1] == '\r')) {
                            msg[len - 1] = '\0';
                        }
                    }
                    hash_message(hx, msg, q);
                    gmp_printf("[+] Mensaje de texto: \"%s\"\n", msg);
                    gmp_printf("[+] Hash obtenido mod q (e): %Zd\n", hx);
                } else {
                    read_mpz_from_input(hx, "\nIngrese el mensaje (numero entero o hex): ");
                    gmp_snprintf(msg, sizeof(msg), "%Zd", hx);
                    if (mpz_cmp(hx, q) >= 0 || mpz_sgn(hx) < 0) {
                        mpz_mod(hx, hx, q);
                        gmp_printf("[+] Mensaje numerico reducido mod q (e): %Zd\n", hx);
                    } else {
                        gmp_printf("[+] Mensaje numerico (e): %Zd\n", hx);
                    }
                }

                if (has_session_sig) {
                    ecdsa_sign_clear(&session_sig);
                    has_session_sig = false;
                }

                printf("\n[*] Firmando mensaje con ecdsa_signature...\n");
                if (ecdsa_signature(&session_sig, priv, p, G, a, b, q, hx) == 0) {
                    has_session_sig = true;
                    mpz_set(session_hx, hx);
                    strncpy(session_msg, msg, sizeof(session_msg) - 1);

                    printf("\n=====================================================\n");
                    printf("               FIRMA DIGITAL GENERADA                \n");
                    printf("=====================================================\n");
                    if (msg_opt == 2) {
                        printf("  Mensaje (texto): \"%s\"\n", msg);
                        gmp_printf("  Hash e (mod q):  %Zd\n", hx);
                    } else {
                        printf("  Mensaje (numero): %s\n", msg);
                        gmp_printf("  Valor e (mod q):  %Zd\n", hx);
                    }
                    gmp_printf("  Firma:           (r, s) = (%Zd, %Zd)\n", session_sig.sign_r, session_sig.sign_s);
                    printf("=====================================================\n");

                    if (save_signature_to_file("firma.txt", msg, hx, &session_sig) == 0) {
                        printf("[+] Firma digital guardada en 'firma.txt'\n");
                    }
                    printf("[*] Firma guardada en sesion para verificacion inmediata.\n\n");
                } else {
                    printf("[-] Error al generar la firma.\n\n");
                }

                mpz_clear(hx);
                ecdsa_kpriv_clear(&priv);
                point_clear(&G);
                mpz_clears(p, a, b, q, NULL);
                break;
            }

            case 3: {
                printf("\n--- Verificacion de Firma ECDSA (ecdsa_sign_verification) ---\n");
                kpub_t pub; ecdsa_kpub_init(&pub);
                ecdsa_sign_t sig; ecdsa_sign_init(&sig);
                mpz_t hx; mpz_init(hx);

                bool use_session = false;
                if (has_session_keys && has_session_sig) {
                    char ans[32];
                    printf("¿Desea verificar la firma y clave publica de la sesion actual? (s/n) [default: s]: ");
                    if (fgets(ans, sizeof(ans), stdin) == NULL || ans[0] == '\n' ||
                        ans[0] == 's' || ans[0] == 'S' || ans[0] == 'y' || ans[0] == 'Y') {
                        use_session = true;
                    }
                }

                if (use_session) {
                    mpz_set(pub.kpub_p, session_keys.keys_pub.kpub_p);
                    mpz_set(pub.kpub_a, session_keys.keys_pub.kpub_a);
                    mpz_set(pub.kpub_b, session_keys.keys_pub.kpub_b);
                    mpz_set(pub.kpub_q, session_keys.keys_pub.kpub_q);
                    point_set(&pub.kpub_A, &session_keys.keys_pub.kpub_A);
                    point_set(&pub.kpub_B, &session_keys.keys_pub.kpub_B);

                    mpz_set(sig.sign_r, session_sig.sign_r);
                    mpz_set(sig.sign_s, session_sig.sign_s);
                    mpz_set(hx, session_hx);
                    printf("[+] Verificando datos de sesion para el mensaje: \"%s\"\n", session_msg);
                } else {
                    printf("\nOrigen de datos para verificacion:\n");
                    printf("  1. Cargar desde archivos ('public_key.txt' y 'firma.txt')\n");
                    printf("  2. Ingresar todos los parametros manualmente\n");
                    printf("Seleccion [1-2] [default: 1]: ");
                    char line[32];
                    int opt_v = 1;
                    if (fgets(line, sizeof(line), stdin) != NULL && line[0] != '\n') {
                        sscanf(line, "%d", &opt_v);
                    }

                    if (opt_v == 1) {
                        char file_msg[512] = {0};
                        if (load_public_key_from_file(&pub, "public_key.txt") == 0 &&
                            load_signature_from_file("firma.txt", file_msg, sizeof(file_msg), hx, &sig) == 0) {
                            printf("[+] Archivos 'public_key.txt' y 'firma.txt' cargados correctamente.\n");
                            if (file_msg[0] != '\0') printf("    Mensaje registrado: \"%s\"\n", file_msg);
                        } else {
                            printf("[-] Error leyendo archivos. Ingrese los datos manualmente.\n");
                            opt_v = 2;
                        }
                    }

                    if (opt_v == 2) {
                        choose_or_input_curve(pub.kpub_p, pub.kpub_a, pub.kpub_b, pub.kpub_q, &pub.kpub_A);
                        input_point(&pub.kpub_B, "Clave Publica Q = B");

                        printf("\nSeleccione el modo del mensaje a verificar:\n");
                        printf("  1. Mensaje como un numero directamente (e = valor numerico)\n");
                        printf("  2. Ingresar texto del mensaje y hashearlo (Toy Hash mod q)\n");
                        printf("Seleccion [1-2] [default: 1]: ");
                        char vmopt[32];
                        int v_msg_opt = 1;
                        if (fgets(vmopt, sizeof(vmopt), stdin) != NULL && vmopt[0] != '\n') {
                            sscanf(vmopt, "%d", &v_msg_opt);
                        }

                        if (v_msg_opt == 2) {
                            char vmsg[512] = {0};
                            printf("\nIngrese el texto del mensaje a verificar: ");
                            if (fgets(vmsg, sizeof(vmsg), stdin) != NULL) {
                                size_t len = strlen(vmsg);
                                if (len > 0 && (vmsg[len - 1] == '\n' || vmsg[len - 1] == '\r')) {
                                    vmsg[len - 1] = '\0';
                                }
                            }
                            hash_message(hx, vmsg, pub.kpub_q);
                            gmp_printf("[+] Hash calculado mod q (e): %Zd\n", hx);
                        } else {
                            read_mpz_from_input(hx, "\nIngrese el mensaje (numero entero o hex): ");
                            if (mpz_cmp(hx, pub.kpub_q) >= 0 || mpz_sgn(hx) < 0) {
                                mpz_mod(hx, hx, pub.kpub_q);
                                gmp_printf("[+] Mensaje reducido mod q (e): %Zd\n", hx);
                            }
                        }

                        read_mpz_from_input(sig.sign_r, "Firma r: ");
                        read_mpz_from_input(sig.sign_s, "Firma s: ");
                    }
                }

                printf("\n[*] Ejecutando ecdsa_sign_verification...\n");
                int valid = ecdsa_sign_verification(pub, sig, hx);

                printf("\n=====================================================\n");
                printf("             RESULTADO DE LA VERIFICACION            \n");
                printf("=====================================================\n");
                if (valid == 1) {
                    printf("  >>> [+] ¡FIRMA VALIDA! <<<\n");
                    printf("  El punto P = u1*A + u2*B cumple P.x = r (mod q).\n");
                    printf("  La autenticidad e integridad del mensaje son autenticas.\n");
                } else {
                    printf("  >>> [-] ¡FIRMA INVALIDA! <<<\n");
                    printf("  La firma no corresponde a la clave publica o el mensaje fue alterado.\n");
                }
                printf("=====================================================\n\n");

                mpz_clear(hx);
                ecdsa_sign_clear(&sig);
                ecdsa_kpub_clear(&pub);
                break;
            }

            case 4: {
                printf("\nSaliendo del programa de Laboratorio 03. ¡Hasta luego!\n\n");
                break;
            }

            default:
                printf("\n[!] Opcion no valida. Seleccione una opcion entre 1 y 4.\n\n");
                break;
        }

    } while (opcion != 4);

    /* Limpieza general al salir */
    if (has_session_keys) ecdsa_keys_clear(&session_keys);
    if (has_session_sig) ecdsa_sign_clear(&session_sig);
    mpz_clear(session_hx);
    gmp_randclear(rng_state);

    return 0;
}
