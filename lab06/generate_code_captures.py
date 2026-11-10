#!/usr/bin/env python3
import os
import re
import html
import subprocess

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "capturas"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAIN_C_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.c"))
WASM_C_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "web", "crypto_wasm.c"))

def highlight_line(line):
    line = html.escape(line)
    comment_part = ""
    if "//" in line:
        before, after = line.split("//", 1)
        comment_part = f'<tspan fill="#6c7086" font-style="italic">// {after}</tspan>'
        line = before

    def str_sub(m):
        return f'<tspan fill="#a6e3a1">{m.group(0)}</tspan>'
    line = re.sub(r'&quot;.*?&quot;', str_sub, line)

    kws = [
        r'\bint\b', r'\bvoid\b', r'\breturn\b', r'\bif\b', r'\belse\b',
        r'\bwhile\b', r'\bfor\b', r'\bdo\b', r'\bconst\b', r'\bsize_t\b',
        r'\bssize_t\b', r'\bmpz_t\b', r'\buint8_t\b', r'\buint32_t\b',
        r'\buint64_t\b', r'\bFILE\b', r'\bbreak\b', r'\bcontinue\b',
        r'\bstruct\b', r'\btypedef\b', r'\bbool\b', r'\bstatic\b', r'\bchar\b',
        r'\bunsigned\b'
    ]
    for kw in kws:
        line = re.sub(kw, r'<tspan fill="#89b4fa" font-weight="bold">\g<0></tspan>', line)

    types_and_consts = [
        r'\bOK\b', r'\bERROR\b', r'\bNULL\b', r'\bMAGIC_RSAC\b', r'\bMAGIC_AESC\b',
        r'\brsa_sc_t\b', r'\brsa_sc_pub_key_t\b', r'\brsa_sc_pri_key_t\b',
        r'\bgmp_randstate_t\b', r'\bEVP_PKEY\b', r'\bEVP_PKEY_CTX\b',
        r'\bEVP_CIPHER_CTX\b', r'\bBIGNUM\b', r'\bRSA_PKCS1_OAEP_PADDING\b',
        r'\bAES_128_KEY_BYTES\b', r'\bWASM_EXPORT\b'
    ]
    for tc in types_and_consts:
        line = re.sub(tc, r'<tspan fill="#fab387" font-weight="bold">\g<0></tspan>', line)

    return line + comment_part

def render_code_card(lines, start_line, title, filename):
    font_size = 11.5
    line_height = 17
    width = 960

    content_height = len(lines) * line_height + 24
    total_height = content_height + 40

    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" viewBox="0 0 {width} {total_height}">')
    svg.append(f'<rect width="{width}" height="{total_height}" fill="#181825" rx="8"/>')
    svg.append(f'<rect width="{width}" height="34" fill="#11111b" rx="8"/>')
    svg.append(f'<rect y="24" width="{width}" height="10" fill="#11111b"/>')

    svg.append('<circle cx="18" cy="17" r="5" fill="#f38ba8"/>')
    svg.append('<circle cx="34" cy="17" r="5" fill="#f9e2af"/>')
    svg.append('<circle cx="50" cy="17" r="5" fill="#a6e3a1"/>')

    t_esc = html.escape(title)
    svg.append(f'<text x="{width/2}" y="21" fill="#cdd6f4" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600" text-anchor="middle">{t_esc}</text>')

    y = 52
    for idx, l in enumerate(lines):
        ln = start_line + idx
        svg.append(f'<text x="45" y="{y}" fill="#585b70" font-family="Menlo, Monaco, Consolas, monospace" font-size="{font_size}" text-anchor="end">{ln}</text>')
        svg.append(f'<line x1="55" y1="{y-12}" x2="55" y2="{y+4}" stroke="#313244" stroke-width="1"/>')
        highlighted = highlight_line(l)
        svg.append(f'<text x="65" y="{y}" fill="#cdd6f4" font-family="Menlo, Monaco, Consolas, monospace" font-size="{font_size}" xml:space="preserve">{highlighted}</text>')
        y += line_height

    svg.append('</svg>')
    svg_str = '\n'.join(svg)

    svg_file = os.path.join(OUTPUT_DIR, filename.replace(".png", ".svg"))
    png_file = os.path.join(OUTPUT_DIR, filename)
    with open(svg_file, "w", encoding="utf-8") as f:
        f.write(svg_str)
    subprocess.run(["/opt/homebrew/bin/rsvg-convert", svg_file, "-o", png_file], check=True)
    if os.path.exists(svg_file):
        os.remove(svg_file)
    print(f"[✓] Captura de código creada: {png_file}")

def extract_lines(all_lines, start, end):
    return all_lines[start - 1 : end]

def main():
    with open(MAIN_C_PATH, "r", encoding="utf-8") as f:
        main_lines = [l.rstrip("\r\n") for l in f.readlines()]

    with open(WASM_C_PATH, "r", encoding="utf-8") as f:
        wasm_lines = [l.rstrip("\r\n") for l in f.readlines()]

    # 1. Sección 1.1: gen_key() (lines 314 to 406)
    render_code_card(extract_lines(main_lines, 314, 406), 314,
                     "main.c — Ejercicio 1.1: gen_key() [Generación de Llaves RSA Escolar con CRT]",
                     "captura_codigo_01_gen_key.png")

    # 2. Sección 1.2: exp_bin() (lines 436 to 476)
    render_code_card(extract_lines(main_lines, 436, 476), 436,
                     "main.c — Ejercicio 1.2: exp_bin() [Algoritmo 1: Square and Multiply(x, H, n)]",
                     "captura_codigo_02_exp_bin.png")

    # 3. Sección 1.3 & 1.4: rsa_encrypt_int() & rsa_decrypt_int() (lines 595 to 630)
    render_code_card(extract_lines(main_lines, 595, 630), 595,
                     "main.c — Ejercicios 1.3 y 1.4: rsa_encrypt_int() y rsa_decrypt_int()",
                     "captura_codigo_03_rsa_encrypt_int.png")

    # 4. Sección 1.4: ctr() (lines 481 to 554)
    render_code_card(extract_lines(main_lines, 481, 554), 481,
                     "main.c — Ejercicio 1.4: ctr() [Descifrado CRT Paso a Paso: Garner y Gauss]",
                     "captura_codigo_04_ctr.png")

    # 5. Sección 2.1: oaep_inspect_crt_params() & oaep_generate_keypair_files() (lines 1124 to 1212)
    render_code_card(extract_lines(main_lines, 1124, 1212), 1124,
                     "main.c — Ejercicio 2.1: oaep_generate_keypair_files() [Llaves RSA-OAEP con CRT en Base64]",
                     "captura_codigo_05_oaep_keygen.png")

    # 6. Sección 2.2: aes128_generate_key() & aes128_ctr_encrypt_file() (lines 1286 to 1372)
    render_code_card(extract_lines(main_lines, 1286, 1372), 1286,
                     "main.c — Ejercicio 2.2: aes128_generate_key() y aes128_ctr_encrypt_file() [AES-128-CTR]",
                     "captura_codigo_06_aes128_ctr.png")

    # 7. Sección 2.3: rsa_oaep_encrypt_key_to_file() (lines 1454 to 1528)
    render_code_card(extract_lines(main_lines, 1454, 1528), 1454,
                     "main.c — Ejercicio 2.3: rsa_oaep_encrypt_key_to_file() [Encapsulado de K con RSA-OAEP en Base64]",
                     "captura_codigo_07_oaep_wrap.png")

    # 8. Sección 2.4: rsa_oaep_decrypt_key_from_file() (lines 1534 to 1626)
    render_code_card(extract_lines(main_lines, 1534, 1626), 1534,
                     "main.c — Ejercicio 2.4: rsa_oaep_decrypt_key_from_file() [Descifrado RSA-OAEP con CRT en Base64]",
                     "captura_codigo_08_oaep_unwrap.png")

    # 9. WebAssembly C Engine: wasm_oaep_encode() & wasm_aes128_ctr_crypt()
    render_code_card(extract_lines(wasm_lines, 435, 515), 435,
                     "web/crypto_wasm.c — Motor C compilado a WebAssembly (wasm_oaep_encode & wasm_oaep_decode)",
                     "captura_codigo_09_wasm_engine.png")

if __name__ == "__main__":
    main()
