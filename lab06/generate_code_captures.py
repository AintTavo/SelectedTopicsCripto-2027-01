#!/usr/bin/env python3
import os
import re
import html
import subprocess

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "capturas"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAIN_C_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.c"))

def highlight_line(line):
    # Escape HTML
    line = html.escape(line)
    # Check comments
    comment_part = ""
    if "//" in line:
        before, after = line.split("//", 1)
        comment_part = f'<tspan fill="#6c7086" font-style="italic">// {after}</tspan>'
        line = before

    # Replace string literals
    def str_sub(m):
        return f'<tspan fill="#a6e3a1">{m.group(0)}</tspan>'
    line = re.sub(r'&quot;.*?&quot;', str_sub, line)

    # Keywords
    kws = [
        r'\bint\b', r'\bvoid\b', r'\breturn\b', r'\bif\b', r'\belse\b',
        r'\bwhile\b', r'\bfor\b', r'\bdo\b', r'\bconst\b', r'\bsize_t\b',
        r'\bssize_t\b', r'\bmpz_t\b', r'\buint8_t\b', r'\buint32_t\b',
        r'\buint64_t\b', r'\bFILE\b', r'\bbreak\b', r'\bcontinue\b',
        r'\bstruct\b', r'\btypedef\b', r'\bbool\b', r'\bstatic\b'
    ]
    for kw in kws:
        line = re.sub(kw, r'<tspan fill="#89b4fa" font-weight="bold">\g<0></tspan>', line)

    # Constants & Types
    types_and_consts = [
        r'\bOK\b', r'\bERROR\b', r'\bNULL\b', r'\bMAGIC_RSAC\b',
        r'\brsa_sc_t\b', r'\brsa_sc_pub_key_t\b', r'\brsa_sc_pri_key_t\b',
        r'\bgmp_randstate_t\b'
    ]
    for tc in types_and_consts:
        line = re.sub(tc, r'<tspan fill="#fab387" font-weight="bold">\g<0></tspan>', line)

    return line + comment_part

def render_code_card(lines, start_line, title, filename):
    font_size = 12
    line_height = 18
    width = 960

    content_height = len(lines) * line_height + 25
    total_height = content_height + 42

    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" viewBox="0 0 {width} {total_height}">')
    svg.append(f'<rect width="{width}" height="{total_height}" fill="#181825" rx="8"/>')
    svg.append(f'<rect width="{width}" height="34" fill="#11111b" rx="8"/>')
    svg.append(f'<rect y="24" width="{width}" height="10" fill="#11111b"/>')

    # macOS window buttons
    svg.append('<circle cx="18" cy="17" r="5" fill="#f38ba8"/>')
    svg.append('<circle cx="34" cy="17" r="5" fill="#f9e2af"/>')
    svg.append('<circle cx="50" cy="17" r="5" fill="#a6e3a1"/>')

    # Window title
    t_esc = html.escape(title)
    svg.append(f'<text x="{width/2}" y="21" fill="#cdd6f4" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600" text-anchor="middle">{t_esc}</text>')

    y = 54
    for idx, l in enumerate(lines):
        ln = start_line + idx
        # line number
        svg.append(f'<text x="45" y="{y}" fill="#585b70" font-family="Menlo, Monaco, Consolas, monospace" font-size="{font_size}" text-anchor="end">{ln}</text>')
        # divider
        svg.append(f'<line x1="55" y1="{y-12}" x2="55" y2="{y+4}" stroke="#313244" stroke-width="1"/>')
        # code
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
        all_lines = f.readlines()
    # strip trailing newline for each line
    all_lines = [l.rstrip("\r\n") for l in all_lines]

    # 1. gen_key (lines 207 to 280 & 281 to 330)
    # Let's extract core logic of gen_key (207 to 275)
    render_code_card(extract_lines(all_lines, 207, 275), 207,
                     "main.c — gen_key() [Generación de primos p, q y exponentes e, d, dp, dq]",
                     "captura_codigo_01_gen_key.png")

    # 2. exp_bin (lines 345 to 389)
    render_code_card(extract_lines(all_lines, 345, 389), 345,
                     "main.c — exp_bin() [Algoritmo 1: Square and Multiply Corregido]",
                     "captura_codigo_02_exp_bin.png")

    # 3. rsa_encrypt_int (lines 521 to 537)
    render_code_card(extract_lines(all_lines, 521, 537), 521,
                     "main.c — rsa_encrypt_int() [Cifrado RSA Escolar de un Entero 0 < m < n]",
                     "captura_codigo_03_rsa_encrypt_int.png")

    # 4. ctr (lines 403 to 468)
    render_code_card(extract_lines(all_lines, 403, 468), 403,
                     "main.c — ctr() [Descifrado por Teorema Chino del Residuo - Garner y Gauss]",
                     "captura_codigo_04_ctr.png")

    # 5. rsa_decrypt_int (lines 544 to 562)
    render_code_card(extract_lines(all_lines, 544, 562), 544,
                     "main.c — rsa_decrypt_int() [Descifrado RSA Escolar con CRT]",
                     "captura_codigo_05_rsa_decrypt_int.png")

    # 6. rsa_encrypt & rsa_decrypt files (core chunking logic) (lines 569 to 630)
    render_code_card(extract_lines(all_lines, 569, 626), 569,
                     "main.c — rsa_encrypt() [Cifrado de Archivos Arbitrarios en Bloques m < n]",
                     "captura_codigo_06_rsa_encrypt_file.png")

    # 7. rsa_decrypt file (lines 661 to 726)
    render_code_card(extract_lines(all_lines, 661, 726), 661,
                     "main.c — rsa_decrypt() [Descifrado de Archivos Arbitrarios con CRT]",
                     "captura_codigo_07_rsa_decrypt_file.png")

    # 8. Persistencia de llaves (lines 763 to 825)
    render_code_card(extract_lines(all_lines, 763, 825), 763,
                     "main.c — rsa_save_pub_key() y rsa_save_priv_key() [Persistencia en Disco]",
                     "captura_codigo_08_persistencia_llaves.png")

if __name__ == "__main__":
    main()
