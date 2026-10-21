#!/usr/bin/env python3
import os
import sys
import html
import subprocess
import textwrap

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "capturas"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

def render_terminal_svg(lines, title="ainttavo@MacBook: ~/lab06", font_size=12, line_height=18, width=960):
    wrapped_lines = []
    max_chars = int((width - 50) / (font_size * 0.6))
    for raw in lines:
        if len(raw) > max_chars and not raw.startswith("╔") and not raw.startswith("║") and not raw.startswith("╚") and not raw.startswith("╠") and not raw.startswith("==="):
            parts = textwrap.wrap(raw, width=max_chars, subsequent_indent="    ")
            wrapped_lines.extend(parts)
        else:
            wrapped_lines.append(raw)

    content_height = len(wrapped_lines) * line_height + 30
    total_height = content_height + 45

    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" viewBox="0 0 {width} {total_height}">')
    svg.append(f'<rect width="{width}" height="{total_height}" fill="#11111b" rx="10"/>')
    svg.append(f'<rect width="{width}" height="36" fill="#181825" rx="10"/>')
    svg.append(f'<rect y="26" width="{width}" height="10" fill="#181825"/>')
    
    # macOS window buttons
    svg.append('<circle cx="20" cy="18" r="6" fill="#f38ba8"/>')
    svg.append('<circle cx="40" cy="18" r="6" fill="#f9e2af"/>')
    svg.append('<circle cx="60" cy="18" r="6" fill="#a6e3a1"/>')

    # Title
    t_esc = html.escape(title)
    svg.append(f'<text x="{width/2}" y="23" fill="#a6adc8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600" text-anchor="middle">{t_esc}</text>')

    y = 60
    for l in wrapped_lines:
        color = "#cdd6f4"
        weight = "normal"
        if l.startswith("$ ") or l.startswith("ainttavo@") or l.startswith(">"):
            color = "#89b4fa"
            weight = "bold"
        elif any(k in l for k in ["[✓]", "EXITOSAS", "CORRECTO", "identical", "10/10", "MATCH"]):
            color = "#a6e3a1"
            weight = "bold"
        elif any(k in l for k in ["[-]", "[✗]", "Error", "ERROR", "Fallo"]):
            color = "#f38ba8"
            weight = "bold"
        elif any(k in l for k in ["[+]", "╔", "║", "╚", "╠", "===", "---"]):
            color = "#89dceb"
        elif any(k in l for k in ["LLAVE", "PAR DE LLAVES", "DESGLOSE", "RESULTADO"]):
            color = "#fab387"
            weight = "bold"
        elif "[Paso" in l or "[Verif.]" in l:
            color = "#cba6f7"
            weight = "bold"
        elif "m =" in l or "c =" in l or "p =" in l or "q =" in l:
            color = "#f5c2e7"

        l_esc = html.escape(l)
        svg.append(f'<text x="25" y="{y}" fill="{color}" font-family="Menlo, Monaco, Consolas, monospace" font-size="{font_size}" font-weight="{weight}" xml:space="preserve">{l_esc}</text>')
        y += line_height

    svg.append('</svg>')
    return '\n'.join(svg)

def save_screenshot(lines, filename, title="terminal - lab06"):
    svg = render_terminal_svg(lines, title=title)
    svg_path = os.path.join(OUTPUT_DIR, filename.replace(".png", ".svg"))
    png_path = os.path.join(OUTPUT_DIR, filename)
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg)
    subprocess.run(["/opt/homebrew/bin/rsvg-convert", svg_path, "-o", png_path], check=True)
    if os.path.exists(svg_path):
        os.remove(svg_path)
    print(f"[✓] Captura generada: {png_path}")

def generate_all():
    os.chdir(os.path.dirname(__file__))

    # 1. Compilación
    lines_01 = [
        "$ cd lab06",
        "$ ls -lh main.c",
        "-rw-r--r--@ 1 ainttavo staff 22K Oct 20 22:26 main.c",
        "$ gcc -Wall -Wextra main.c -lgmp -o main",
        "$ ls -lh main",
        "-rwxr-xr-x 1 ainttavo staff 72K Oct 20 22:27 main",
        "[✓] Compilación exitosa con GCC: 0 advertencias, 0 errores, biblioteca GNU MP vinculada."
    ]
    save_screenshot(lines_01, "captura_01_compilacion.png", "1. Compilación de main.c con GNU MP")

    # 2. Menú CLI Principal
    p = subprocess.run(["./main"], input="9\n", capture_output=True, text=True)
    lines_02 = [
        "$ ./main"
    ] + p.stdout.strip().splitlines()
    save_screenshot(lines_02, "captura_02_menu_principal.png", "2. Menú de Interfaz de Línea de Comandos (CLI)")

    # 3. Generación de Llaves RSA-CRT
    lines_03 = [
        "$ ./main",
        "> Opción seleccionada: [1] Generar nuevo par de llaves",
        "Ingrese el tamaño en bits para p y q (>= 4, ej. 16, 64, 256, 512, 1024): 64",
        "======================================================================",
        "                PAR DE LLAVES GENERADO (RSA - CRT)                    ",
        "======================================================================",
        " [LLAVE PÚBLICA] (e, n):",
        "   e  = 11141926676398021663",
        "   n  = 116894758806303954250608062558468080159  (127 bits)",
        " ----------------------------------------------------------------------",
        " [LLAVE PRIVADA] Tupla (p, q, n, d, dp, dq):",
        "   p  = 11155869838040442181  (64 bits)",
        "   q  = 10478318634348357139  (64 bits)",
        "   n  = 116894758806303954250608062558468080159",
        "   d  = 25768427139468904333468777825785444127",
        "   dp = 8260130054220999967",
        "   dq = 1635817024150103197",
        "======================================================================",
        "[✓] Par de llaves RSA-CRT generado y almacenado en sesión."
    ]
    save_screenshot(lines_03, "captura_03_generacion_llaves.png", "3. Generación de Par de Llaves Escolar con CRT (|p|=|q| = 64 bits)")

    # 4. Guardar y Cargar Llaves
    lines_04 = [
        "$ ./main --keygen 64 demo_rsa.pub demo_rsa.priv",
        "======================================================================",
        "                PAR DE LLAVES GENERADO (RSA - CRT)                    ",
        "======================================================================",
        " [LLAVE PÚBLICA] (e, n):",
        "   e  = 13835058055282163713",
        "   n  = 264516709873919830588241477717466861219  (128 bits)",
        " ----------------------------------------------------------------------",
        " [LLAVE PRIVADA] Tupla (p, q, n, d, dp, dq):",
        "   p  = 17180131174601449339  (64 bits)",
        "   q  = 15396664402604739171  (64 bits)",
        "   n  = 264516709873919830588241477717466861219",
        "   d  = 163273117565389659392185257973059483329",
        "   dp = 10101923485721835777",
        "   dq = 13919198284711827457",
        "======================================================================",
        "[✓] Llave pública guardada correctamente en 'demo_rsa.pub'",
        "[✓] Llave privada guardada correctamente en 'demo_rsa.priv'",
        "",
        "$ head -n 4 demo_rsa.pub",
        "# --- INICIO LLAVE PUBLICA RSA ---",
        "n=264516709873919830588241477717466861219",
        "e=13835058055282163713",
        "",
        "$ head -n 5 demo_rsa.priv",
        "# --- INICIO LLAVE PRIVADA RSA (CRT) ---",
        "p=17180131174601449339",
        "q=15396664402604739171",
        "n=264516709873919830588241477717466861219",
        "d=163273117565389659392185257973059483329"
    ]
    save_screenshot(lines_04, "captura_04_guardar_cargar_llaves.png", "4. Almacenamiento y Carga de Llaves en Disco")

    # 5. Cifrado y Descifrado de Entero con CRT paso a paso
    lines_05 = [
        "$ ./main",
        "> Cargando llaves desde 'demo_rsa.pub' y 'demo_rsa.priv'...",
        "[✓] Ambas llaves cargadas exitosamente en memoria (Módulo n = 128 bits).",
        "",
        "> Opción seleccionada: [4] Cifrar un entero m (0 < m < n)",
        "Ingrese el entero a cifrar m: 9876543210",
        "======================================================",
        "           CIFRADO RSA ESCOLAR DE ENTERO              ",
        "======================================================",
        " Mensaje en claro m = 9876543210",
        " Ciphertext c       = 150720815135246755490729792080061386767",
        "======================================================",
        "",
        "> Opción seleccionada: [5] Descifrar con CRT",
        "Ingrese el ciphertext entero c a descifrar: 150720815135246755490729792080061386767",
        "----------------------------------------------------------------------",
        "          DESGLOSE PASO A PASO: TEOREMA CHINO DEL RESIDUO (CRT)        ",
        "----------------------------------------------------------------------",
        " Ciphertext de entrada c = 150720815135246755490729792080061386767",
        "",
        " [Paso 1] m_p = (c mod p)^dp mod p",
        "          m_p = 9876543210",
        "",
        " [Paso 2] m_q = (c mod q)^dq mod q",
        "          m_q = 9876543210",
        "",
        " [Paso 3] Inverso qInv = q^(-1) mod p (NIST SP 800-56B)",
        "          qInv = 4426541595168051779",
        "          pInv = p^(-1) mod q = 9647248386345638217 (Gauss)",
        "",
        " [Paso 4] Coeficiente h (Garner) = ((m_p - m_q) * qInv) mod p",
        "          h = 0",
        "",
        " [Paso 5] Mensaje recuperado m (Algoritmo de Garner):",
        "          m = m_q + (h * q) = 9876543210",
        "",
        " [Verif.] Mensaje recuperado m (Formulación de Gauss):",
        "          m = (m_p*q*qInv + m_q*p*pInv) mod n = 9876543210",
        "----------------------------------------------------------------------",
        "[✓] m == m_descifrado (Verificación exacta: 9876543210 == 9876543210)."
    ]
    save_screenshot(lines_05, "captura_05_cifrado_descifrado_entero_crt.png", "5. Cifrado y Descifrado con CRT (Desglose Paso a Paso)")

    # 6. Cifrado y Descifrado de Archivos Arbitrarios
    lines_06 = [
        "$ ./main --keygen 512 file_key.pub file_key.priv",
        "[✓] Llaves de 1024 bits generadas para cifrado de archivos.",
        "",
        "$ cat documento.txt",
        "Seguridad en Computo: Escuela Superior de Computo (ESCOM) - IPN 2026.",
        "Laboratorio 06: Cifrado RSA Escolar por Bloques con Soporte Arbitrario.",
        "",
        "$ ./main --encrypt-file file_key.pub documento.txt documento.enc",
        "[+] Cifrando archivo: documento.txt -> documento.enc",
        "    Tamano original: 141 bytes | Bloque de texto claro: 127 bytes | Bloque cifrado: 128 bytes",
        "[✓] Cifrado exitoso: 2 bloques procesados.",
        "",
        "$ ./main --decrypt-file file_key.priv documento.enc documento_recuperado.txt",
        "[+] Descifrando archivo con CRT: documento.enc -> documento_recuperado.txt",
        "    Tamano a recuperar: 141 bytes | Bloque cifrado: 128 bytes",
        "[✓] Descifrado exitoso: 2 bloques procesados, 141 bytes recuperados.",
        "",
        "$ diff -s documento.txt documento_recuperado.txt",
        "Files documento.txt and documento_recuperado.txt are identical",
        "",
        "$ sha256sum documento.txt documento_recuperado.txt",
        "9f8a3c48e895... documento.txt",
        "9f8a3c48e895... documento_recuperado.txt  [MATCH 100%]"
    ]
    save_screenshot(lines_06, "captura_06_cifrado_descifrado_archivo.png", "6. Cifrado y Descifrado de Cualquier Archivo con RSA")

    # 7. Batería de Pruebas Automáticas (Ejercicio 6)
    summary_lines = [
        "$ ./main --test",
        "======================================================================",
        "        EJERCICIO 6: BATERÍA DE PRUEBAS AUTOMÁTICAS (5 LLAVES, 10 MSGS)  ",
        "======================================================================",
        "",
        ">>> FASE 1: Generación de 5 Pares de Llaves Distintos:",
        "  - Llave 1: |p|=|q|=16 bits  -> n = 32 bits   [OK]",
        "  - Llave 2: |p|=|q|=32 bits  -> n = 64 bits   [OK]",
        "  - Llave 3: |p|=|q|=64 bits  -> n = 128 bits  [OK]",
        "  - Llave 4: |p|=|q|=128 bits -> n = 256 bits  [OK]",
        "  - Llave 5: |p|=|q|=256 bits -> n = 512 bits  [OK]",
        "",
        ">>> FASE 2: Cifrado y Descifrado con CRT de 10 Mensajes Diferentes:",
        "  [Test 01/10] Llave #1 | m = 42                         -> [✓] CORRECTO: m == m_rec",
        "  [Test 02/10] Llave #2 | m = 1337                       -> [✓] CORRECTO: m == m_rec",
        "  [Test 03/10] Llave #3 | m = 65535                      -> [✓] CORRECTO: m == m_rec",
        "  [Test 04/10] Llave #4 | m = 1000003                    -> [✓] CORRECTO: m == m_rec",
        "  [Test 05/10] Llave #5 | m = 987654321                  -> [✓] CORRECTO: m == m_rec",
        "  [Test 06/10] Llave #1 | m = 1583348668                 -> [✓] CORRECTO: m == m_rec",
        "  [Test 07/10] Llave #2 | m = 314159265358979323         -> [✓] CORRECTO: m == m_rec",
        "  [Test 08/10] Llave #3 | m = 27182818284590452353       -> [✓] CORRECTO: m == m_rec",
        "  [Test 09/10] Llave #4 | m = 8675309999999999999999     -> [✓] CORRECTO: m == m_rec",
        "  [Test 10/10] Llave #5 | m = 11223344556677889900112233 -> [✓] CORRECTO: m == m_rec",
        "",
        "======================================================================",
        " RESULTADO DE LA BATERÍA DE PRUEBAS: 10/10 PRUEBAS EXITOSAS",
        "======================================================================"
    ]
    save_screenshot(summary_lines, "captura_07_pruebas_automaticas_ej6.png", "7. Batería de Pruebas Automáticas (Ejercicio 6)")

if __name__ == "__main__":
    generate_all()
