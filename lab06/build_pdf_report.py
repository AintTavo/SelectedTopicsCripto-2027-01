#!/usr/bin/env python3
import os
import sys
import zlib
import struct
import textwrap

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CAPTURAS_DIR = os.path.join(BASE_DIR, "capturas")
OUTPUT_PDF = os.path.join(BASE_DIR, "Reporte_Laboratorio06_Seccion1.pdf")

def png_to_rgb(png_path):
    with open(png_path, 'rb') as f:
        data = f.read()
    assert data[:8] == b'\x89PNG\r\n\x1a\n', f"Not a PNG: {png_path}"
    idx = 8
    idat = bytearray()
    w, h, colortype = 0, 0, 2
    while idx < len(data):
        length = struct.unpack('>I', data[idx:idx+4])[0]
        ctype = data[idx+4:idx+8]
        cdata = data[idx+8:idx+8+length]
        idx += 12 + length
        if ctype == b'IHDR':
            w, h, _, colortype, _, _, _ = struct.unpack('>IIBBBBB', cdata[:13])
        elif ctype == b'IDAT':
            idat.extend(cdata)
        elif ctype == b'IEND':
            break

    raw = zlib.decompress(bytes(idat))
    bpp = 3 if colortype == 2 else 4
    rgb = bytearray()
    pos = 0
    stride = w * bpp
    prev_row = bytearray(stride)
    for y in range(h):
        ft = raw[pos]
        pos += 1
        row = bytearray(raw[pos:pos+stride])
        pos += stride
        if ft == 1:
            for x in range(bpp, stride):
                row[x] = (row[x] + row[x - bpp]) & 0xff
        elif ft == 2:
            for x in range(stride):
                row[x] = (row[x] + prev_row[x]) & 0xff
        elif ft == 3:
            for x in range(stride):
                l = row[x - bpp] if x >= bpp else 0
                u = prev_row[x]
                row[x] = (row[x] + ((l + u) >> 1)) & 0xff
        elif ft == 4:
            for x in range(stride):
                a = row[x - bpp] if x >= bpp else 0
                b = prev_row[x]
                c = prev_row[x - bpp] if x >= bpp else 0
                p = a + b - c
                pa = abs(p - a)
                pb = abs(p - b)
                pc = abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                row[x] = (row[x] + pr) & 0xff
        prev_row = row
        if bpp == 3:
            rgb.extend(row)
        else:
            for x in range(w):
                rgb.extend(row[x*4 : x*4 + 3])
    return w, h, bytes(rgb)

def escape_pdf(text):
    text = text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
    # Convert common unicode characters to ascii/latin1 representations
    text = text.replace('\u2022', '-')
    text = text.replace('á', 'a').replace('é', 'e').replace('í', 'i').replace('ó', 'o').replace('ú', 'u')
    text = text.replace('Á', 'A').replace('É', 'E').replace('Í', 'I').replace('Ó', 'O').replace('Ú', 'U')
    text = text.replace('ñ', 'n').replace('Ñ', 'N').replace('—', '-').replace('–', '-')
    text = text.replace('“', '"').replace('”', '"').replace('’', "'").replace('‘', "'")
    text = text.replace('≥', '>=').replace('≤', '<=').replace('≠', '!=').replace('≡', '=').replace('→', '->')
    text = text.replace('ϕ', 'phi').replace('λ', 'lambda').replace('✓', '[OK]').replace('✗', '[X]')
    # Ensure all remaining non-latin1 characters are mapped to ascii safely
    return text.encode('ascii', errors='replace').decode('ascii')

class PDFDoc:
    def __init__(self):
        self.pages = []
        self.images = {} # name -> (w, h, compressed_rgb)
        self.page_width = 612 # Letter
        self.page_height = 792
        self.margin_left = 40
        self.margin_right = 40
        self.print_width = self.page_width - self.margin_left - self.margin_right

    def add_image_resource(self, name, filepath):
        if name not in self.images:
            w, h, rgb = png_to_rgb(filepath)
            comp = zlib.compress(rgb)
            self.images[name] = (w, h, comp)
        return self.images[name]

    def create_page(self):
        page = Page(self)
        self.pages.append(page)
        return page

    def compile(self, output_path):
        objs = []
        # obj 1: Catalog
        # obj 2: Pages
        # obj 3..: Fonts
        # obj next: Images
        # obj next: Pages and Contents

        pdf_parts = [b'%PDF-1.4\n']
        offsets = []

        def write_obj(num, body):
            offsets.append(sum(len(p) for p in pdf_parts))
            pdf_parts.append(f'{num} 0 obj\n'.encode('latin1'))
            pdf_parts.append(body if isinstance(body, bytes) else body.encode('latin1'))
            pdf_parts.append(b'\nendobj\n')

        # Fonts
        font_helv = 3
        font_bold = 4
        font_cour = 5
        font_cour_b = 6

        # Allocate object IDs
        # 1: Catalog, 2: Pages
        cur_id = 7
        image_ids = {}
        for img_name, (w, h, comp) in self.images.items():
            image_ids[img_name] = cur_id
            cur_id += 1

        page_ids = []
        content_ids = []
        for p in self.pages:
            page_ids.append(cur_id)
            cur_id += 1
            content_ids.append(cur_id)
            cur_id += 1

        # Write Catalog
        write_obj(1, '<< /Type /Catalog /Pages 2 0 R >>')

        # Write Pages tree
        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        write_obj(2, f'<< /Type /Pages /Kids [{kids_str}] /Count {len(self.pages)} >>')

        # Write Standard Fonts
        write_obj(font_helv, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
        write_obj(font_bold, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>')
        write_obj(font_cour, '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>')
        write_obj(font_cour_b, '<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>')

        # Write Images
        for img_name, (w, h, comp) in self.images.items():
            iid = image_ids[img_name]
            header = f'<< /Type /XObject /Subtype /Image /Width {w} /Height {h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(comp)} >>\nstream\n'
            write_obj(iid, header.encode('latin1') + comp + b'\nendstream')

        # Write Pages & Content Streams
        total_p = len(self.pages)
        for idx, p in enumerate(self.pages):
            pid = page_ids[idx]
            cid = content_ids[idx]

            # XObject dict for page
            xobj_entries = " ".join(f"/{img_name} {image_ids[img_name]} 0 R" for img_name in p.used_images)
            xobj_dict = f'/XObject << {xobj_entries} >>' if p.used_images else ''

            res_dict = f'<< /Font << /F1 {font_helv} 0 R /F2 {font_bold} 0 R /F3 {font_cour} 0 R /F4 {font_cour_b} 0 R >> {xobj_dict} >>'
            write_obj(pid, f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.page_width} {self.page_height}] /Resources {res_dict} /Contents {cid} 0 R >>')

            # Render Page stream with header/footer
            stream_bytes = p.render_stream(idx + 1, total_p)
            write_obj(cid, f'<< /Length {len(stream_bytes)} >>\nstream\n'.encode('latin1') + stream_bytes + b'\nendstream')

        # xref
        xref_pos = sum(len(p) for p in pdf_parts)
        total_objs = cur_id - 1
        pdf_parts.append(f'xref\n0 {total_objs + 1}\n0000000000 65535 f \n'.encode('latin1'))
        for off in offsets:
            pdf_parts.append(f'{off:010d} 00000 n \n'.encode('latin1'))

        pdf_parts.append(f'trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n'.encode('latin1'))

        with open(output_path, 'wb') as f:
            f.write(b''.join(pdf_parts))
        print(f"[✓] Documento PDF compilado con éxito: {output_path} ({os.path.getsize(output_path)} bytes, {len(self.pages)} páginas)")

class Page:
    def __init__(self, doc):
        self.doc = doc
        self.commands = []
        self.used_images = set()
        self.cursor_y = doc.page_height - 50 # start from top

    def draw_header_footer(self, page_num, total_pages):
        res = []
        # Header banner line
        res.append("q 0.2 0.4 0.7 rg 0.2 0.4 0.7 RG 1 w")
        res.append(f"{self.doc.margin_left} {self.doc.page_height - 35} m {self.doc.page_width - self.doc.margin_right} {self.doc.page_height - 35} l S Q")

        # Header text
        header_text = escape_pdf("IPN - ESCOM | Temas Selectos de Criptografia | Lab 06: RSA Escolar con CRT")
        res.append(f"BT /F2 8 Tf 0.3 0.3 0.4 rg {self.doc.margin_left} {self.doc.page_height - 30} Td ({header_text}) Tj ET")

        # Footer line
        res.append("q 0.7 0.7 0.7 rg 0.7 0.7 0.7 RG 0.5 w")
        res.append(f"{self.doc.margin_left} 40 m {self.doc.page_width - self.doc.margin_right} 40 l S Q")

        # Footer text
        footer_text = escape_pdf("Reporte de Laboratorio - Seccion 1")
        page_str = escape_pdf(f"Pagina {page_num} de {total_pages}")
        res.append(f"BT /F1 8 Tf 0.4 0.4 0.4 rg {self.doc.margin_left} 28 Td ({footer_text}) Tj ET")
        res.append(f"BT /F2 8 Tf 0.2 0.4 0.7 rg {self.doc.page_width - self.doc.margin_right - 60} 28 Td ({page_str}) Tj ET")
        return "\n".join(res)

    def add_title(self, text, subtitle=None):
        t_esc = escape_pdf(text)
        self.cursor_y -= 14
        self.commands.append(f"BT /F2 16 Tf 0.1 0.2 0.5 rg {self.doc.margin_left} {self.cursor_y} Td ({t_esc}) Tj ET")
        if subtitle:
            self.cursor_y -= 14
            s_esc = escape_pdf(subtitle)
            self.commands.append(f"BT /F1 9 Tf 0.3 0.3 0.3 rg {self.doc.margin_left} {self.cursor_y} Td ({s_esc}) Tj ET")
        self.cursor_y -= 12

    def add_section(self, text):
        self.cursor_y -= 12
        t_esc = escape_pdf(text)
        # Colored bar
        self.commands.append(f"q 0.15 0.35 0.65 rg {self.doc.margin_left} {self.cursor_y - 2} 4 14 re f Q")
        self.commands.append(f"BT /F2 11 Tf 0.1 0.2 0.4 rg {self.doc.margin_left + 10} {self.cursor_y} Td ({t_esc}) Tj ET")
        self.cursor_y -= 14

    def add_paragraph(self, text, bold_prefix="", font_size=8.5, line_spacing=11):
        full_text = bold_prefix + text
        # Word wrap
        wrapped = textwrap.wrap(full_text, width=105)
        for i, line in enumerate(wrapped):
            self.cursor_y -= line_spacing
            l_esc = escape_pdf(line)
            font = "/F2" if (i == 0 and bold_prefix) else "/F1"
            self.commands.append(f"BT {font} {font_size} Tf 0.15 0.15 0.15 rg {self.doc.margin_left} {self.cursor_y} Td ({l_esc}) Tj ET")
        self.cursor_y -= 4

    def add_bullet(self, bold_text, desc, font_size=8.5, line_spacing=11):
        combined = f"• {bold_text}: {desc}"
        wrapped = textwrap.wrap(combined, width=102, subsequent_indent="   ")
        for i, line in enumerate(wrapped):
            self.cursor_y -= line_spacing
            l_esc = escape_pdf(line)
            self.commands.append(f"BT /F1 {font_size} Tf 0.15 0.15 0.15 rg {self.doc.margin_left + 8} {self.cursor_y} Td ({l_esc}) Tj ET")
        self.cursor_y -= 3

    def add_image(self, img_name, png_path, max_h=230, caption=None):
        self.doc.add_image_resource(img_name, png_path)
        self.used_images.add(img_name)
        w, h, _ = self.doc.images[img_name]

        # Calculate fit width
        avail_w = self.doc.print_width
        avail_h = max_h

        scale_w = avail_w / w
        scale_h = avail_h / h
        scale = min(scale_w, scale_h)

        disp_w = int(w * scale)
        disp_h = int(h * scale)
        disp_x = self.doc.margin_left + (avail_w - disp_w) // 2
        disp_y = self.cursor_y - disp_h

        # Frame border around screenshot
        self.commands.append(f"q 0.85 0.88 0.92 rg 0.65 0.7 0.78 RG 0.5 w {disp_x - 2} {disp_y - 2} {disp_w + 4} {disp_h + 4} re S Q")
        # Draw image
        self.commands.append(f"q {disp_w} 0 0 {disp_h} {disp_x} {disp_y} cm /{img_name} Do Q")
        self.cursor_y = disp_y - 8

        if caption:
            c_esc = escape_pdf(f"Figura: {caption}")
            self.commands.append(f"BT /F2 8 Tf 0.25 0.35 0.5 rg {self.doc.margin_left} {self.cursor_y} Td ({c_esc}) Tj ET")
            self.cursor_y -= 10
        self.cursor_y -= 6

    def render_stream(self, page_num, total_pages):
        header_footer = self.draw_header_footer(page_num, total_pages)
        page_content = "\n".join(self.commands)
        full = f"{header_footer}\n{page_content}"
        return full.encode('latin1', errors='replace')

def build_pdf():
    doc = PDFDoc()

    # =========================================================================
    # PAGINA 1: Portada, Objetivos y Diagnóstico de Corrección de Errores
    # =========================================================================
    p1 = doc.create_page()
    p1.add_title("Reporte Tecnico: Laboratorio 06 (CTR y RSA-OAEP)",
                 "Seccion 1: Schoolbook RSA con Teorema Chino del Residuo (CRT) | Octubre 2026")

    p1.add_section("1. Informacion General y Objetivos")
    p1.add_paragraph("Este reporte documenta la implementacion, correccion, persistencia y verificacion integral de la Seccion 1 del Laboratorio 06. El criptosistema esta programado en lenguaje C sobre arquitectura macOS empleando la biblioteca de precision arbitraria GNU MP (GMP). Se incluye la correccion de 5 defectos logicos del codigo base, la construccion de una interfaz CLI amigable, persistencia de llaves en disco (.pub y .priv) y el soporte para cifrado/descifrado de cualquier tipo de archivo con fidelidad binaria exacta.")

    p1.add_section("2. Diagnostico y Correccion de Errores Criticos del Codigo Base")
    p1.add_bullet("Semilla del RNG (gen_key)", "Se inicializaba el generador aleatorio de GMP pero nunca se establecia semilla con gmp_randseed_ui, generando siempre las mismas llaves identicas. Se corrigio leyendo entropia real de /dev/urandom.")
    p1.add_bullet("Inversion en Ciclo de 'e' (gen_key)", "El codigo original contenia 'while (gcd == 1);', lo cual descartaba coprimos validos y aceptaba no coprimos. Se corrigio buscando coprimos impares con phi(n) distintos de 3 y 65537.")
    p1.add_bullet("Error en Exponente CRT d_q (gen_key)", "Calculaba mpz_mod con p - 1 en vez de q - 1. Se corrigio aplicando d_q = d mod (q - 1).")
    p1.add_bullet("Indexacion e Iteracion en exp_bin", "El bucle iteraba desde len hasta i > 0, excluyendo el bit 0 y testeando un bit fuera de rango. Al inicializar r = x mod n, se ajusto para iterar desde t - 2 hasta 0 de forma matematicamente exacta.")
    p1.add_bullet("Condicion Fatal en ctr (CRT)", "Verificaba 'if (mpz_odd_p(p) != 0) return ERROR;'. Como p es un primo impar, la funcion fallaba inmediatamente para cualquier primo valido. Se elimino y se implemento Garner y Gauss.")

    p1.add_section("3. Compilacion Limpia del Codigo Fuente")
    p1.add_paragraph("Compilacion del aplicativo mediante GCC con banderas de advertencia maximas (-Wall -Wextra) y enlace a GNU MP:")
    p1.add_image("img_compilacion", os.path.join(CAPTURAS_DIR, "captura_01_compilacion.png"), max_h=90,
                 caption="Compilacion limpia sin errores ni advertencias (0 warnings, 0 errors)")

    # =========================================================================
    # PAGINA 2: Código Fuente Sección 1 (Parte A: Generación y Exponenciación)
    # =========================================================================
    p2 = doc.create_page()
    p2.add_title("Funciones Especificas de la Seccion 1 (Codigo Fuente)",
                 "Implementacion de gen_key() y Algoritmo 1: exp_bin() [Square and Multiply]")

    p2.add_section("1. Funcion gen_key(): Generacion de Llaves RSA-CRT (|p| = |q| >= 4 bits)")
    p2.add_paragraph("Genera primos independientes p y q con mpz_nextprime de GMP, calcula n = p * q, phi(n) = (p - 1)(q - 1), busca aleatoriamente e coprimo cumpliendo e != 3 y e != 2^16+1, calcula d = e^(-1) mod phi(n), y obtiene los exponentes CRT d_p = d mod (p - 1) y d_q = d mod (q - 1):")
    p2.add_image("cod_gen_key", os.path.join(CAPTURAS_DIR, "captura_codigo_01_gen_key.png"), max_h=280,
                 caption="main.c - Implementacion de gen_key() con generacion de primos y calculo de tuplas")

    p2.add_section("2. Funcion exp_bin(): Algoritmo 1: Square and Multiply(x, H, n)")
    p2.add_paragraph("Implementa la exponenciacion rapida modular de izquierda a derecha. Al asignar r <- x mod n (bit mas significativo), el ciclo itera estrictamente desde i = t - 2 descendiendo hasta 0:")
    p2.add_image("cod_exp_bin", os.path.join(CAPTURAS_DIR, "captura_codigo_02_exp_bin.png"), max_h=180,
                 caption="main.c - Algoritmo 1: Square and Multiply con correccion matematica de ciclo")

    # =========================================================================
    # PAGINA 3: Código Fuente Sección 1 (Parte B: Cifrado Escolar y CRT)
    # =========================================================================
    p3 = doc.create_page()
    p3.add_title("Funciones Especificas de la Seccion 1 (Codigo Fuente)",
                 "Implementacion de rsa_encrypt_int(), ctr() y rsa_decrypt_int()")

    p3.add_section("1. Funcion rsa_encrypt_int(): Cifrado Escolar de un Entero (0 < m < n)")
    p3.add_paragraph("Valida el rango del mensaje claro 0 < m < n y calcula c = m^e mod n usando exp_bin:")
    p3.add_image("cod_enc_int", os.path.join(CAPTURAS_DIR, "captura_codigo_03_rsa_encrypt_int.png"), max_h=90,
                 caption="main.c - rsa_encrypt_int() para cifrado de enteros escolares")

    p3.add_section("2. Funcion ctr(): Teorema Chino del Residuo con Desglose de Valores")
    p3.add_paragraph("Calcula m_p = c^dp mod p, m_q = c^dq mod q, qInv = q^(-1) mod p, coeficiente de Garner h = ((m_p - m_q) * qInv) mod p, reconstruye m = m_q + (h * q) e imprime cada valor intermedio requerido por el Ejercicio 4:")
    p3.add_image("cod_ctr", os.path.join(CAPTURAS_DIR, "captura_codigo_04_ctr.png"), max_h=270,
                 caption="main.c - ctr() implementando Algoritmo de Garner y comprobacion con Gauss")

    p3.add_section("3. Funcion rsa_decrypt_int(): Descifrado Escolar con CRT")
    p3.add_paragraph("Valida 0 < c < n y ejecuta el descifrado mediante el Teorema Chino del Residuo:")
    p3.add_image("cod_dec_int", os.path.join(CAPTURAS_DIR, "captura_codigo_05_rsa_decrypt_int.png"), max_h=90,
                 caption="main.c - rsa_decrypt_int() para descifrado de enteros escolares")

    # =========================================================================
    # PAGINA 4: Código Fuente Sección 1 (Parte C: Cifrado Archivos y Persistencia)
    # =========================================================================
    p4 = doc.create_page()
    p4.add_title("Cifrado de Archivos Arbitrarios y Persistencia de Llaves",
                 "Implementacion de rsa_encrypt(), rsa_decrypt() y manejo de llaves en disco")

    p4.add_section("1. rsa_encrypt() y rsa_decrypt(): Cifrado/Descifrado de Cualquier Archivo")
    p4.add_paragraph("Divide el archivo en bloques de tamano (n_len - 1) bytes, garantizando que cada bloque satisfaga 0 <= m < n. Escribe cabecera RSAC y serializa cada bloque cifrado en n_len bytes exactos:")
    p4.add_image("cod_enc_file", os.path.join(CAPTURAS_DIR, "captura_codigo_06_rsa_encrypt_file.png"), max_h=230,
                 caption="main.c - rsa_encrypt() procesando archivos binarios/texto por bloques")

    p4.add_section("2. Persistencia en Disco: Guardado y Carga de Llaves (.pub y .priv)")
    p4.add_paragraph("Funciones para serializar e importar llaves públicas (e, n) y privadas (p, q, n, d, dp, dq):")
    p4.add_image("cod_persist", os.path.join(CAPTURAS_DIR, "captura_codigo_08_persistencia_llaves.png"), max_h=230,
                 caption="main.c - rsa_save_pub_key() y rsa_save_priv_key() para almacenamiento persistente")

    # =========================================================================
    # PAGINA 5: Evidencias de Ejecución (CLI y Llaves)
    # =========================================================================
    p5 = doc.create_page()
    p5.add_title("Evidencias de Ejecucion del Programa",
                 "Interfaz CLI Interactiva, Generacion y Persistencia de Llaves")

    p5.add_section("1. Interfaz de Linea de Comandos (CLI Interactiva)")
    p5.add_paragraph("Menu principal que centraliza todas las operaciones de forma amigable:")
    p5.add_image("exec_menu", os.path.join(CAPTURAS_DIR, "captura_02_menu_principal.png"), max_h=160,
                 caption="Ejecucion del menu interactivo por consola con 9 opciones de usuario")

    p5.add_section("2. Generacion de Par de Llaves Escolar con CRT")
    p5.add_paragraph("Generacion de tuplas completas de llave publica y privada para p y q de 64 bits (n = 127 bits):")
    p5.add_image("exec_keygen", os.path.join(CAPTURAS_DIR, "captura_03_generacion_llaves.png"), max_h=190,
                 caption="Generacion del par de llaves: tupla publica (e, n) y tupla privada (p, q, n, d, dp, dq)")

    p5.add_section("3. Guardado y Carga de Llaves en Disco")
    p5.add_paragraph("Persistencia en archivos demo_rsa.pub y demo_rsa.priv y su lectura verificada:")
    p5.add_image("exec_save_load", os.path.join(CAPTURAS_DIR, "captura_04_guardar_cargar_llaves.png"), max_h=180,
                 caption="Almacenamiento y carga de llaves en el dispositivo en formato texto estructurado")

    # =========================================================================
    # PAGINA 6: Evidencias de Ejecución (Cifrado CRT y Archivos)
    # =========================================================================
    p6 = doc.create_page()
    p6.add_title("Evidencias de Ejecucion del Programa",
                 "Descifrado con Teorema Chino del Residuo y Cifrado de Archivos")

    p6.add_section("1. Cifrado y Descifrado con Desglose Paso a Paso de CRT")
    p6.add_paragraph("Cifrado de m = 9876543210 y descifrado con CRT mostrando m_p, m_q, qInv, pInv, h y m:")
    p6.add_image("exec_crt", os.path.join(CAPTURAS_DIR, "captura_05_cifrado_descifrado_entero_crt.png"), max_h=300,
                 caption="Desglose de valores intermedios durante el descifrado con Teorema Chino del Residuo")

    p6.add_section("2. Cifrado y Descifrado de Archivos Arbitrarios (Texto e Imagen/Binario)")
    p6.add_paragraph("Cifrado en bloques de un archivo, descifrado con CRT y comprobacion diff -s y SHA-256:")
    p6.add_image("exec_files", os.path.join(CAPTURAS_DIR, "captura_06_cifrado_descifrado_archivo.png"), max_h=230,
                 caption="Cifrado y descifrado de archivo comprobando identidad binaria al 100% (diff -s)")

    # =========================================================================
    # PAGINA 7: Batería de Pruebas (Ej. 6) y Respuestas NIST SP 800-56B Rev. 2
    # =========================================================================
    p7 = doc.create_page()
    p7.add_title("Bateria de Pruebas (Ejercicio 6) y Preguntas NIST",
                 "Verificacion formal de 5 llaves, 10 mensajes y respuestas teoricas NIST SP 800-56B Rev. 2")

    p7.add_section("1. Bateria de Pruebas Automaticas (Ejercicio 6: 5 llaves, 10 mensajes)")
    p7.add_paragraph("Generacion de 5 pares de llaves (16, 32, 64, 128, 256 bits) y cifrado/descifrado con CRT de 10 mensajes con verificacion al 100%:")
    p7.add_image("exec_test", os.path.join(CAPTURAS_DIR, "captura_07_pruebas_automaticas_ej6.png"), max_h=210,
                 caption="Resultado exitoso de la bateria de pruebas automaticas (10/10 pruebas superadas)")

    p7.add_section("2. Respuestas a las Preguntas de la Seccion 3 (NIST SP 800-56B Rev. 2)")
    p7.add_bullet("1. Titulo de la norma", "Recommendation for Pair-Wise Key Establishment Using Integer Factorization Cryptography (Rev 2, 2019).")
    p7.add_bullet("2. Formatos de Llave Privada (Sec 6.2.2)", "1) Basico: (n, d); 2) Factores Primos: (p, q, d); 3) CRT: (n, e, d, p, q, dP, dQ, qInv).")
    p7.add_bullet("3. Valores en Formato CRT", "Consta de 8 valores: n (modulo), e (exp publico), d (exp privado), p y q (primos), dP = d mod (p-1), dQ = d mod (q-1), qInv = q^(-1) mod p.")
    p7.add_bullet("4. Niveles de Seguridad (Sec 6.3)", "2048 bits -> 112 bits; 3072 bits -> 128 bits; 4096 bits -> 152 bits. En el codigo, se establece mediante: gen_key(&current_keys, bits);.")
    p7.add_bullet("5. Descifrado CRT (Sec 7.1.2.3)", "Algoritmo de Garner: m_p = c^dP mod p, m_q = c^dQ mod q, h = ((m_p - m_q)*qInv) mod p, m = m_q + (q * h) mod n.")
    p7.add_bullet("6. KTS-OAEP (Sec 9.2)", "Esquema asimetrico de transporte de claves simetricas (ej. AES) usando RSA con relleno probabilisticamente seguro OAEP.")

    doc.compile(OUTPUT_PDF)

if __name__ == "__main__":
    build_pdf()
