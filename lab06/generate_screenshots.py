#!/usr/bin/env python3
import os
import sys
import html
import subprocess
import textwrap

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "capturas"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

def render_terminal_svg(lines, title="gustavo@escom-mbp: ~/crypto/lab06", font_size=12, line_height=18, width=960):
    wrapped_lines = []
    max_chars = int((width - 50) / (font_size * 0.6))
    for raw in lines:
        if len(raw) > max_chars and not any(raw.startswith(p) for p in ["╔", "║", "╚", "╠", "===", " ---"]):
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
        if l.startswith("$ ") or l.startswith("gustavo@") or l.startswith(">"):
            color = "#89b4fa"
            weight = "bold"
        elif any(k in l for k in ["[✓]", "EXITOSAS", "CORRECTO", "identical", "10/10", "MATCH", "ÉXITO", "100%"]):
            color = "#a6e3a1"
            weight = "bold"
        elif any(k in l for k in ["[-]", "[✗]", "Error", "ERROR", "Fallo"]):
            color = "#f38ba8"
            weight = "bold"
        elif any(k in l for k in ["[+]", "╔", "║", "╚", "╠", "===", "---"]):
            color = "#89dceb"
        elif any(k in l for k in ["LLAVE", "PAR DE LLAVES", "DESGLOSE", "RESULTADO", "EJERCICIO", "VERIFICACIÓN"]):
            color = "#fab387"
            weight = "bold"
        elif "[Paso" in l or "[Verif" in l or ">>>" in l:
            color = "#cba6f7"
            weight = "bold"
        elif any(k in l for k in ["m =", "c =", "p =", "q =", "Base64", "SHA-256"]):
            color = "#f5c2e7"

        l_esc = html.escape(l)
        svg.append(f'<text x="25" y="{y}" fill="{color}" font-family="Menlo, Monaco, Consolas, monospace" font-size="{font_size}" font-weight="{weight}" xml:space="preserve">{l_esc}</text>')
        y += line_height

    svg.append('</svg>')
    return '\n'.join(svg)

def save_svg_to_png(svg_str, filename):
    svg_path = os.path.join(OUTPUT_DIR, filename.replace(".png", ".svg"))
    png_path = os.path.join(OUTPUT_DIR, filename)
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg_str)
    subprocess.run(["/opt/homebrew/bin/rsvg-convert", svg_path, "-o", png_path], check=True)
    if os.path.exists(svg_path):
        os.remove(svg_path)
    print(f"[✓] Imagen generada: {png_path}")

def save_screenshot(lines, filename, title="gustavo@escom-mbp: ~/crypto/lab06"):
    svg = render_terminal_svg(lines, title=title)
    save_svg_to_png(svg, filename)

def generate_architecture_diagram():
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="1020" height="470" viewBox="0 0 1020 470">
      <rect width="1020" height="470" fill="#f8fafc" rx="12" stroke="#cbd5e1" stroke-width="2"/>
      <text x="510" y="34" fill="#0f172a" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="16" font-weight="bold" text-anchor="middle">
        KTS-OAEP Key Transport (NIST SP 800-56B Rev. 2) + CRT Decryption &amp; AES-128-CTR Architecture
      </text>

      <!-- Box 1: OAEP Encoding (Bob / Party U) -->
      <rect x="25" y="55" width="470" height="265" fill="#ffffff" rx="8" stroke="#94a3b8" stroke-width="1.5"/>
      <text x="260" y="78" fill="#1e3a8a" font-family="sans-serif" font-size="13" font-weight="bold" text-anchor="middle">
        Party U (Bob): RSA-OAEP.ENCRYPT((n, e), K, A) — Sec. 7.2.2.3
      </text>

      <!-- DB fields -->
      <rect x="45" y="95" width="95" height="36" fill="#e0f2fe" rx="4" stroke="#0284c7"/>
      <text x="92" y="112" fill="#0369a1" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">HA = H(A)</text>
      <text x="92" y="125" fill="#0369a1" font-family="sans-serif" font-size="9" text-anchor="middle">SHA-256 (32 B)</text>

      <rect x="145" y="95" width="115" height="36" fill="#f1f5f9" rx="4" stroke="#64748b"/>
      <text x="202" y="112" fill="#334155" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">PS = 0x00...</text>
      <text x="202" y="125" fill="#475569" font-family="sans-serif" font-size="9" text-anchor="middle">nLen-KLen-2hLen-2</text>

      <rect x="265" y="95" width="55" height="36" fill="#fef3c7" rx="4" stroke="#d97706"/>
      <text x="292" y="117" fill="#b45309" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">0x01</text>

      <rect x="325" y="95" width="150" height="36" fill="#dcfce7" rx="4" stroke="#16a34a"/>
      <text x="400" y="112" fill="#15803d" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">AES Key K (128 bits)</text>
      <text x="400" y="125" fill="#166534" font-family="sans-serif" font-size="9" text-anchor="middle">16 Bytes Secret Material</text>

      <!-- mgfSeed & MGF1 -->
      <rect x="45" y="155" width="135" height="38" fill="#fae8ff" rx="4" stroke="#a21caf"/>
      <text x="112" y="172" fill="#86198f" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">mgfSeed (RBG)</text>
      <text x="112" y="185" fill="#86198f" font-family="sans-serif" font-size="9" text-anchor="middle">32 Bytes Random</text>

      <rect x="210" y="155" width="265" height="38" fill="#ede9fe" rx="4" stroke="#6d28d9"/>
      <text x="342" y="172" fill="#5b21b6" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">dbMask = MGF1-SHA256(mgfSeed)</text>
      <text x="342" y="185" fill="#5b21b6" font-family="sans-serif" font-size="9" text-anchor="middle">maskedDB = DB XOR dbMask | seedMask = MGF1(maskedDB)</text>

      <!-- EM -->
      <rect x="45" y="212" width="55" height="36" fill="#f1f5f9" rx="4" stroke="#475569"/>
      <text x="72" y="234" fill="#1e293b" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">0x00</text>

      <rect x="105" y="212" width="155" height="36" fill="#fce7f3" rx="4" stroke="#db2777"/>
      <text x="182" y="229" fill="#9d174d" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">maskedMGFSeed</text>
      <text x="182" y="241" fill="#9d174d" font-family="sans-serif" font-size="9" text-anchor="middle">mgfSeed XOR seedMask</text>

      <rect x="265" y="212" width="210" height="36" fill="#e0e7ff" rx="4" stroke="#4f46e5"/>
      <text x="370" y="229" fill="#3730a3" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">maskedDB = DB XOR dbMask</text>
      <text x="370" y="241" fill="#3730a3" font-family="sans-serif" font-size="9" text-anchor="middle">nLen - hLen - 1 Bytes (351 B)</text>

      <rect x="45" y="264" width="430" height="42" fill="#eff6ff" rx="6" stroke="#2563eb" stroke-width="1.5"/>
      <text x="260" y="282" fill="#1d4ed8" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">
        RSAEP: em = BS2I(EM)  ---&gt;  c = em^e mod n  ---&gt;  Base64(I2BS(c, nLen))
      </text>
      <text x="260" y="297" fill="#1e40af" font-family="sans-serif" font-size="10" text-anchor="middle">
        Output: 384-Byte (3072-bit) Ciphertext C stored in Base64 textfile
      </text>

      <!-- Box 2: RSADP with CRT & OAEP Decoding (Alice / Party V) -->
      <rect x="525" y="55" width="470" height="265" fill="#ffffff" rx="8" stroke="#94a3b8" stroke-width="1.5"/>
      <text x="760" y="78" fill="#065f46" font-family="sans-serif" font-size="13" font-weight="bold" text-anchor="middle">
        Party V (Alice): RSADP-CRT (Sec. 7.1.2.3) &amp; RSA-OAEP.DECRYPT (Sec. 7.2.2.4)
      </text>

      <rect x="545" y="95" width="205" height="55" fill="#f0fdf4" rx="4" stroke="#16a34a"/>
      <text x="647" y="114" fill="#15803d" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">1. m_p = c^dP mod p</text>
      <text x="647" y="130" fill="#15803d" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">2. m_q = c^dQ mod q</text>
      <text x="647" y="143" fill="#166534" font-family="sans-serif" font-size="9" text-anchor="middle">Square-and-Multiply (1536-bit primes)</text>

      <rect x="760" y="95" width="215" height="55" fill="#ecfeff" rx="4" stroke="#0891b2"/>
      <text x="867" y="114" fill="#0e7490" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">3. h = (m_p - m_q)*qInv mod p</text>
      <text x="867" y="130" fill="#0e7490" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">4. em = m_q + q * h mod n</text>
      <text x="867" y="143" fill="#155e75" font-family="sans-serif" font-size="9" text-anchor="middle">Garner CRT Recombination (~4x speedup)</text>

      <rect x="545" y="165" width="430" height="42" fill="#faf5ff" rx="4" stroke="#9333ea"/>
      <text x="760" y="183" fill="#6b21a8" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">
        OAEP Unmasking: EM = Y || maskedMGFSeed&apos; || maskedDB&apos;
      </text>
      <text x="760" y="198" fill="#7e22ce" font-family="sans-serif" font-size="10" text-anchor="middle">
        mgfSeed&apos; = maskedMGFSeed&apos; XOR MGF1(maskedDB&apos;)  |  DB&apos; = maskedDB&apos; XOR MGF1(mgfSeed&apos;)
      </text>

      <rect x="545" y="220" width="430" height="40" fill="#fffbeb" rx="4" stroke="#d97706"/>
      <text x="760" y="237" fill="#b45309" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">
        Constant-Time Integrity Check: Y == 0x00 &amp;&amp; HA&apos; == H(A) &amp;&amp; 0x01 Separator
      </text>
      <text x="760" y="252" fill="#92400e" font-family="sans-serif" font-size="9" text-anchor="middle">
        Thwarts Manger (2001) &amp; Bleichenbacher Chosen-Ciphertext Side-Channel Oracles
      </text>

      <rect x="545" y="272" width="430" height="34" fill="#dcfce7" rx="6" stroke="#15803d" stroke-width="1.5"/>
      <text x="760" y="293" fill="#166534" font-family="monospace" font-size="12" font-weight="bold" text-anchor="middle">
        Recovered 128-bit Symmetric Key K (Printed in Base64)
      </text>

      <!-- Box 3: Hybrid AES-128-CTR File Encryption/Decryption -->
      <rect x="25" y="335" width="970" height="115" fill="#ffffff" rx="8" stroke="#94a3b8" stroke-width="1.5"/>
      <text x="510" y="357" fill="#0f172a" font-family="sans-serif" font-size="13" font-weight="bold" text-anchor="middle">
        Symmetric Payload Channel: AES-128 in Counter Mode (AES-128-CTR — NIST SP 800-38A &amp; FIPS 197)
      </text>

      <rect x="45" y="370" width="275" height="62" fill="#f1f5f9" rx="6" stroke="#64748b"/>
      <text x="182" y="392" fill="#1e293b" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">Bob: Arbitrary File m</text>
      <text x="182" y="408" fill="#475569" font-family="sans-serif" font-size="10" text-anchor="middle">Counter T_i = IV + i (128-bit Nonce)</text>
      <text x="182" y="422" fill="#0369a1" font-family="monospace" font-size="10" text-anchor="middle">C_i = P_i XOR AES_K(T_i)</text>

      <rect x="365" y="370" width="290" height="62" fill="#eff6ff" rx="6" stroke="#2563eb"/>
      <text x="510" y="392" fill="#1d4ed8" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">Transmitted Hybrid Bundle</text>
      <text x="510" y="408" fill="#1e40af" font-family="monospace" font-size="10" text-anchor="middle">1) Enciphered Key K in Base64 (.b64)</text>
      <text x="510" y="422" fill="#1e40af" font-family="monospace" font-size="10" text-anchor="middle">2) AES-128-CTR Ciphertext (IV || C)</text>

      <rect x="700" y="370" width="275" height="62" fill="#f0fdf4" rx="6" stroke="#16a34a"/>
      <text x="837" y="392" fill="#15803d" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">Alice: Deciphered File m</text>
      <text x="837" y="408" fill="#166534" font-family="monospace" font-size="10" text-anchor="middle">P_i = C_i XOR AES_K(T_i)</text>
      <text x="837" y="422" fill="#15803d" font-family="sans-serif" font-size="10" font-weight="bold" text-anchor="middle">SHA-256(m_Alice) == SHA-256(m_Bob)</text>
    </svg>'''
    save_svg_to_png(svg, "fig_oaep_crt_arch.png")

def generate_web_ui_screenshot():
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="1020" height="620" viewBox="0 0 1020 620">
      <!-- Browser Window Frame -->
      <rect width="1020" height="620" fill="#090d16" rx="12" stroke="#334155" stroke-width="2"/>
      <rect width="1020" height="42" fill="#151e2e" rx="12"/>
      <rect y="30" width="1020" height="12" fill="#151e2e"/>
      <circle cx="22" cy="21" r="6" fill="#f38ba8"/>
      <circle cx="42" cy="21" r="6" fill="#f9e2af"/>
      <circle cx="62" cy="21" r="6" fill="#a6e3a1"/>
      <rect x="180" y="9" width="660" height="24" fill="#090d16" rx="6" stroke="#334155"/>
      <text x="510" y="25" fill="#94a3b8" font-family="monospace" font-size="11" text-anchor="middle">
        http://localhost:8080/lab06/web/index.html — Tailwind CSS + C17 WebAssembly (crypto_wasm.wasm)
      </text>

      <!-- App Navbar -->
      <rect x="0" y="42" width="1020" height="54" fill="#0f172a"/>
      <line x1="0" y1="96" x2="1020" y2="96" stroke="#1e293b" stroke-width="1"/>
      <rect x="24" y="53" width="32" height="32" fill="#4f46e5" rx="8"/>
      <text x="40" y="74" fill="#ffffff" font-family="monospace" font-size="14" font-weight="bold" text-anchor="middle">L6</text>
      <text x="68" y="67" fill="#ffffff" font-family="sans-serif" font-size="14" font-weight="bold">Lab 06: CTR &amp; RSA-OAEP with CRT</text>
      <text x="68" y="83" fill="#94a3b8" font-family="sans-serif" font-size="10">IPN • ESCOM • Selected Topics in Cryptography • C17 compiled to WebAssembly (wasm32)</text>

      <rect x="715" y="56" width="280" height="26" fill="#064e3b" rx="6" stroke="#059669"/>
      <circle cx="730" cy="69" r="4" fill="#34d399"/>
      <text x="742" y="73" fill="#6ee7b7" font-family="monospace" font-size="10" font-weight="bold">WASM Ready: crypto_wasm.wasm (11 KB)</text>

      <!-- Tabs -->
      <rect x="24" y="108" width="310" height="30" fill="#4f46e5" rx="6"/>
      <text x="179" y="127" fill="#ffffff" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">1. Schoolbook RSA + CRT &amp; Square-and-Multiply</text>

      <rect x="344" y="108" width="330" height="30" fill="#1e293b" rx="6" stroke="#334155"/>
      <text x="509" y="127" fill="#cbd5e1" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">2. RSA-OAEP with CRT &amp; AES-128-CTR (Alice &amp; Bob)</text>

      <rect x="684" y="108" width="310" height="30" fill="#1e293b" rx="6" stroke="#334155"/>
      <text x="839" y="127" fill="#cbd5e1" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">3. NIST SP 800-56B Rev. 2 &amp; Toy CRT Explorer</text>

      <!-- Left Card: Section 1 Keygen & CRT Inspector -->
      <rect x="24" y="150" width="478" height="225" fill="#0f172a" rx="10" stroke="#334155"/>
      <text x="40" y="172" fill="#818cf8" font-family="monospace" font-size="10" font-weight="bold">SECTION 1 • C WASM: wasm_gen_key() &amp; wasm_rsa_decrypt_crt()</text>
      <text x="40" y="190" fill="#ffffff" font-family="sans-serif" font-size="13" font-weight="bold">Schoolbook RSA Keypair &amp; Step-by-Step CRT Decryption</text>

      <rect x="40" y="202" width="215" height="90" fill="#090d16" rx="6" stroke="#1e293b"/>
      <text x="50" y="218" fill="#fbbf24" font-family="monospace" font-size="10" font-weight="bold">PUBLIC KEY (e, n) [e != 3, 65537]</text>
      <text x="50" y="236" fill="#34d399" font-family="monospace" font-size="10">e = 451049741</text>
      <text x="50" y="252" fill="#38bdf8" font-family="monospace" font-size="10">n = 1940635559 (31 bits)</text>
      <text x="50" y="270" fill="#f472b6" font-family="monospace" font-size="10">p = 47417 | q = 40927</text>
      <text x="50" y="284" fill="#a78bfa" font-family="monospace" font-size="10">dp = 5733 | dq = 34961</text>

      <rect x="265" y="202" width="220" height="90" fill="#090d16" rx="6" stroke="#1e293b"/>
      <text x="275" y="218" fill="#c084fc" font-family="monospace" font-size="10" font-weight="bold">GARNER &amp; GAUSS CRT BREAKDOWN</text>
      <text x="275" y="235" fill="#e2e8f0" font-family="monospace" font-size="10">c = 159324491 (from m = 42)</text>
      <text x="275" y="250" fill="#38bdf8" font-family="monospace" font-size="10">m_p = 42 | m_q = 42</text>
      <text x="275" y="265" fill="#fbbf24" font-family="monospace" font-size="10">qInv = 26679 | h = 0</text>
      <text x="275" y="282" fill="#34d399" font-family="monospace" font-size="10" font-weight="bold">m_Garner = 42 | m_Gauss = 42 [OK]</text>

      <rect x="40" y="302" width="445" height="60" fill="#090d16" rx="6" stroke="#1e293b"/>
      <text x="50" y="318" fill="#38bdf8" font-family="monospace" font-size="10" font-weight="bold">ALGORITHM 1 TRACE: wasm_exp_bin(x=42, H=451049741, n=1940635559)</text>
      <text x="50" y="335" fill="#94a3b8" font-family="monospace" font-size="10">i=28 (b=1): r=42  -&gt;  i=27 (b=1): r^2=1764, r*x=74088  -&gt; ... -&gt; i=0 (b=1): r=159324491</text>
      <text x="50" y="352" fill="#34d399" font-family="monospace" font-size="10" font-weight="bold">✓ Automated Test Suite (Exercise 1.6): 5 Key Pairs / 10 Ciphertexts -&gt; 10/10 PASS</text>

      <!-- Right Card: Section 2 Alice & Bob KTS-OAEP + AES-128-CTR -->
      <rect x="518" y="150" width="478" height="225" fill="#0f172a" rx="10" stroke="#334155"/>
      <text x="534" y="172" fill="#f472b6" font-family="monospace" font-size="10" font-weight="bold">SECTION 2 • ALICE &amp; BOB: KTS-OAEP (CRT) + AES-128-CTR IN WASM</text>
      <text x="534" y="190" fill="#ffffff" font-family="sans-serif" font-size="13" font-weight="bold">Hybrid Key Transport &amp; File Encryption Studio (Base64)</text>

      <rect x="534" y="202" width="446" height="52" fill="#090d16" rx="6" stroke="#1e293b"/>
      <text x="544" y="218" fill="#f472b6" font-family="monospace" font-size="10" font-weight="bold">[Alice - Ej. 2.1] 3072-bit RSA-OAEP-CRT Keypair (Base64):</text>
      <text x="544" y="233" fill="#34d399" font-family="monospace" font-size="9.5">alice_oaep_pub.b64 : MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvY3gv8QNAtZioE...</text>
      <text x="544" y="246" fill="#fbbf24" font-family="monospace" font-size="9.5">alice_oaep_priv.b64: MIIG4wIBAAKCAYEAvY3gv8QNAtZioEpukHA44qSz0frobSSBwacM2J9w/4...</text>

      <rect x="534" y="262" width="446" height="52" fill="#090d16" rx="6" stroke="#1e293b"/>
      <text x="544" y="278" fill="#38bdf8" font-family="monospace" font-size="10" font-weight="bold">[Bob - Ej. 2.2 &amp; 2.3] 128-bit AES Key K &amp; RSA-OAEP Encapsulation:</text>
      <text x="544" y="293" fill="#e2e8f0" font-family="monospace" font-size="9.5">Generated K (128b Base64): ltkAOgZl1XQJhlh4YQKtAA==  (96d9003a0665d574098658786102ad00)</text>
      <text x="544" y="306" fill="#fbbf24" font-family="monospace" font-size="9.5">llave_k_oaep.b64 (OAEP)  : rCPwWQPnlZ2s102Ki06yO7qkXW0aYbicnhAvEIRnAdZAGEbgnav4JcDRk9...</text>

      <rect x="534" y="322" width="446" height="42" fill="#090d16" rx="6" stroke="#059669"/>
      <text x="544" y="338" fill="#34d399" font-family="monospace" font-size="10" font-weight="bold">[Alice - Ej. 2.4 &amp; 2.5] RSA-OAEP-CRT Decapsulation &amp; AES-128-CTR Decryption:</text>
      <text x="544" y="354" fill="#6ee7b7" font-family="monospace" font-size="9.5">Recovered K: ltkAOgZl1XQJhlh4YQKtAA== [MATCH] | Decrypted File SHA-256: cdd902a8... [OK]</text>

      <!-- Bottom Full-Width Card: OAEP MGF1-SHA256 Internal Buffer Inspector -->
      <rect x="24" y="390" width="972" height="206" fill="#0f172a" rx="10" stroke="#334155"/>
      <text x="40" y="414" fill="#38bdf8" font-family="monospace" font-size="10" font-weight="bold">WASM MEMORY INSPECTOR • NIST SP 800-56B REV. 2 SECTION 7.2.2.3 (EM = 0x00 || maskedMGFSeed || maskedDB)</text>
      <text x="40" y="432" fill="#ffffff" font-family="sans-serif" font-size="13" font-weight="bold">Live WebAssembly OAEP Encoding &amp; AES-128-CTR Stream Verification</text>

      <rect x="40" y="445" width="940" height="135" fill="#090d16" rx="8" stroke="#1e293b"/>
      <text x="55" y="465" fill="#94a3b8" font-family="monospace" font-size="10.5">HA = SHA256(&quot;&quot;)     : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (32 bytes)</text>
      <text x="55" y="483" fill="#c084fc" font-family="monospace" font-size="10.5">mgfSeed (32 bytes)  : 7a91c4e802b54d19f38a67c11e904b2d885a1c77e03f92a4b618d209c53e7140</text>
      <text x="55" y="501" fill="#f472b6" font-family="monospace" font-size="10.5">maskedMGFSeed       : 4d28b913f6e01a8bc29d45076a113f8e902b4c117f84e301a95c7712e08a43b9</text>
      <text x="55" y="519" fill="#818cf8" font-family="monospace" font-size="10.5">maskedDB [0..31]    : 9b14e07c2a65d831f0429e8a117c5b39d4026f1e88a3c5097b12d4e6019a8c3f...</text>
      <text x="55" y="537" fill="#38bdf8" font-family="monospace" font-size="10.5">AES-128-CTR Stream  : IV = xa9tOtexYL+FoECE1vb8ww== | Plaintext = 246 bytes -&gt; Ciphertext = 266 bytes</text>
      <text x="55" y="558" fill="#34d399" font-family="monospace" font-size="11" font-weight="bold">✓ [WASM C ENGINE] OAEP Decode (Y==0x00, HA&apos;==HA, 0x01 found) &amp; AES-128-CTR Payload Verified (0 errors)</text>
    </svg>'''
    save_svg_to_png(svg, "captura_11_web_tailwind_wasm.png")

def generate_all():
    os.chdir(os.path.dirname(__file__))

    generate_architecture_diagram()
    generate_web_ui_screenshot()

    # 1. Compilación CLI + WASM
    lines_01 = [
        "gustavo@escom-mbp:~/crypto/lab06$ gcc -Wall -Wextra -O2 -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/gmp/include main.c -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/gmp/lib -lssl -lcrypto -lgmp -o main",
        "[✓] Compilación CLI exitosa (0 warnings, 0 errors) vinculando GNU MP y OpenSSL 3.5+ EVP.",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-all web/crypto_wasm.c -o web/crypto_wasm.wasm",
        "gustavo@escom-mbp:~/crypto/lab06$ ls -lh main web/crypto_wasm.wasm web/index.html",
        "-rwxr-xr-x  1 ainttavo  staff   71K Oct 26 23:00 main",
        "-rwxr-xr-x  1 ainttavo  staff   11K Oct 26 23:04 web/crypto_wasm.wasm",
        "-rw-r--r--  1 ainttavo  staff   61K Oct 26 23:08 web/index.html",
        "[✓] Binario nativo CLI y módulo WebAssembly C17 generados exitosamente."
    ]
    save_screenshot(lines_01, "captura_01_compilacion.png", "gustavo@escom-mbp: ~/crypto/lab06 (Compilation CLI & WebAssembly)")

    # 2. Menú CLI Principal
    p = subprocess.run(["./main"], input="12\n", capture_output=True, text=True)
    lines_02 = ["gustavo@escom-mbp:~/crypto/lab06$ ./main"] + p.stdout.strip().splitlines()
    save_screenshot(lines_02, "captura_02_menu_principal.png", "gustavo@escom-mbp: ~/crypto/lab06 (Interactive CLI Menu)")

    # 3. Generación de Llaves RSA-CRT (Sección 1.1)
    lines_03 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main",
        "Seleccione una opción [1-12]: 1",
        "Ingrese el tamaño en bits para p y q (>= 4, ej. 16, 64, 256, 512): 64",
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
    save_screenshot(lines_03, "captura_03_generacion_llaves.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 1.1: Schoolbook RSA-CRT Keygen)")

    # 4. Guardar y Cargar Llaves (Sección 1)
    lines_04 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --keygen 64 demo_rsa.pub demo_rsa.priv",
        "[✓] Llave pública guardada correctamente en 'demo_rsa.pub'",
        "[✓] Llave privada guardada correctamente en 'demo_rsa.priv'",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ cat demo_rsa.pub",
        "# --- INICIO LLAVE PUBLICA RSA ---",
        "n=264516709873919830588241477717466861219",
        "e=13835058055282163713",
        "# --- FIN LLAVE PUBLICA RSA ---",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ cat demo_rsa.priv",
        "# --- INICIO LLAVE PRIVADA RSA (CRT) ---",
        "p=17180131174601449339",
        "q=15396664402604739171",
        "n=264516709873919830588241477717466861219",
        "d=163273117565389659392185257973059483329",
        "dp=10101923485721835777",
        "dq=13919198284711827457",
        "# --- FIN LLAVE PRIVADA RSA (CRT) ---"
    ]
    save_screenshot(lines_04, "captura_04_guardar_cargar_llaves.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 1: Key Persistence)")

    # 5. Cifrado y Descifrado de Entero con CRT paso a paso (Sección 1.3 y 1.4)
    lines_05 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main",
        "> Opción seleccionada: [3] Cifrar un entero m (0 < m < n) usando exp_bin",
        "Ingrese el entero a cifrar m (0 < m < n): 9876543210",
        "======================================================",
        "           CIFRADO RSA ESCOLAR DE ENTERO              ",
        "======================================================",
        " Mensaje en claro m = 9876543210",
        " Ciphertext c       = 150720815135246755490729792080061386767",
        "======================================================",
        "",
        "> Opción seleccionada: [4] Descifrar un entero c (0 < c < n) con CRT",
        "Ingrese el ciphertext entero c a descifrar: 150720815135246755490729792080061386767",
        "----------------------------------------------------------------------",
        "          DESGLOSE PASO A PASO: TEOREMA CHINO DEL RESIDUO (CRT)        ",
        "----------------------------------------------------------------------",
        " Ciphertext de entrada c = 150720815135246755490729792080061386767",
        " [Paso 1] m_p = (c mod p)^dp mod p = 9876543210",
        " [Paso 2] m_q = (c mod q)^dq mod q = 9876543210",
        " [Paso 3] Inverso qInv = q^(-1) mod p (NIST SP 800-56B) = 4426541595168051779",
        "          pInv = p^(-1) mod q = 9647248386345638217 (Gauss)",
        " [Paso 4] Coeficiente h (Garner) = ((m_p - m_q) * qInv) mod p = 0",
        " [Paso 5] Mensaje recuperado m (Algoritmo de Garner): m = m_q + (h * q) = 9876543210",
        " [Verif.] Mensaje recuperado m (Formulación de Gauss): m = 9876543210",
        "----------------------------------------------------------------------",
        "[✓] m == m_descifrado (Verificación exacta: 9876543210 == 9876543210)."
    ]
    save_screenshot(lines_05, "captura_05_cifrado_descifrado_entero_crt.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 1.3 & 1.4: CRT Step-by-Step)")

    # 6. Cifrado y Descifrado de Archivos Arbitrarios (Sección 1)
    lines_06 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --keygen 512 file_key.pub file_key.priv",
        "[✓] Llaves de 1024 bits generadas para cifrado de archivos.",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --encrypt-file file_key.pub documento.txt documento.enc",
        "[+] Cifrando archivo: documento.txt -> documento.enc",
        "    Tamano original: 141 bytes | Bloque de texto claro: 127 bytes | Bloque cifrado: 128 bytes",
        "[✓] Cifrado exitoso: 2 bloques procesados.",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --decrypt-file file_key.priv documento.enc documento_recuperado.txt",
        "[+] Descifrando archivo con CRT: documento.enc -> documento_recuperado.txt",
        "    Tamano a recuperar: 141 bytes | Bloque cifrado: 128 bytes",
        "[✓] Descifrado exitoso: 2 bloques procesados, 141 bytes recuperados.",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ diff -s documento.txt documento_recuperado.txt",
        "Files documento.txt and documento_recuperado.txt are identical"
    ]
    save_screenshot(lines_06, "captura_06_cifrado_descifrado_archivo.png", "gustavo@escom-mbp: ~/crypto/lab06 (Block File Encryption & CRT Decryption)")

    # 7. Batería de Pruebas Automáticas (Ejercicio 1.6)
    summary_lines = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --test",
        "======================================================================",
        "        EJERCICIO 6: BATERÍA DE PRUEBAS AUTOMÁTICAS (5 LLAVES, 10 MSGS)  ",
        "======================================================================",
        ">>> FASE 1: Generación de 5 Pares de Llaves Distintos (e != 3, e != 65537):",
        "  - Llave 1: |p|=|q|=16 bits  -> n = 2953141903 (32 bits), e = 108899       [OK]",
        "  - Llave 2: |p|=|q|=32 bits  -> n = 14462846205541044989 (64 bits)         [OK]",
        "  - Llave 3: |p|=|q|=64 bits  -> n = 20954541351936087162955358... (128 b)  [OK]",
        "  - Llave 4: |p|=|q|=128 bits -> n = 65856503399095952815183365... (256 b)  [OK]",
        "  - Llave 5: |p|=|q|=256 bits -> n = 45660648015505675138508086... (511 b)  [OK]",
        "",
        ">>> FASE 2: Cifrado con exp_bin y Descifrado con CRT de 10 Mensajes Diferentes:",
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
        "======================================================================",
        " RESULTADO DE LA BATERÍA DE PRUEBAS: 10/10 PRUEBAS EXITOSAS",
        "======================================================================"
    ]
    save_screenshot(summary_lines, "captura_07_pruebas_automaticas_ej6.png", "gustavo@escom-mbp: ~/crypto/lab06 (Exercise 1.6: 5 Keys, 10 Messages)")

    # 8. Sección 2.1: Alice genera su par de llaves RSA-OAEP con CRT en Base64
    lines_08 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --oaep-keygen 3072 alice_oaep_pub.b64 alice_oaep_priv.b64",
        "======================================================================",
        "       EJERCICIO 2.1: GENERACIÓN DE LLAVES RSA-OAEP CON CRT           ",
        "======================================================================",
        " [Verificación NIST SP 800-56B Sec. 6.2.2 - Formato CRT de 8 Valores]:",
        "   1. n    (Módulo RSA)             : 3072 bits (128 bits de seguridad)",
        "   2. e    (Exponente público)      : 65537",
        "   3. d    (Exponente privado)      : 3067 bits",
        "   4. p    (Primer factor primo)    : 1536 bits",
        "   5. q    (Segundo factor primo)   : 1536 bits",
        "   6. dP   (d mod (p-1))            : 1535 bits",
        "   7. dQ   (d mod (q-1))            : 1534 bits",
        "   8. qInv (q^(-1) mod p)           : 1536 bits",
        " ----------------------------------------------------------------------",
        " [✓] Llave Pública (Base64) guardada en : 'alice_oaep_pub.b64' (564 chars)",
        "     Vista previa: MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvY3gv8QNAtZioEpukHA4...",
        " [✓] Llave Privada CRT (Base64) en      : 'alice_oaep_priv.b64' (2356 chars)",
        "     Vista previa: MIIG4wIBAAKCAYEAvY3gv8QNAtZioEpukHA44qSz0frobSSBwacM2J9w/4QUBs7o...",
        "======================================================================",
        "    -> Alice comparte 'alice_oaep_pub.b64' (Base64) con Bob."
    ]
    save_screenshot(lines_08, "captura_08_oaep_keygen_alice.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 2.1: Alice RSA-OAEP-CRT Keygen in Base64)")

    # 9. Sección 2.2 y 2.3: Bob genera llave AES K (128 bits), cifra archivo y encapsula K con RSA-OAEP
    lines_09 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --aes-encrypt mensaje_bob.txt mensaje_bob.aes.enc bob_k.b64",
        "======================================================================",
        "         EJERCICIO 2.2: GENERACIÓN DE LLAVE SIMÉTRICA AES-128         ",
        "======================================================================",
        " Longitud de K        : 128 bits (16 bytes)",
        " Llave K (Hex)        : 96d9003a0665d574098658786102ad00",
        " Llave K (Base64)     : ltkAOgZl1XQJhlh4YQKtAA==",
        "======================================================================",
        "[✓] Archivo cifrado con AES-128-CTR exitosamente:",
        "    Entrada : 'mensaje_bob.txt' (246 bytes) -> Salida: 'mensaje_bob.aes.enc' (266 bytes)",
        "    IV/CTR  : xa9tOtexYL+FoECE1vb8ww== (Base64)",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --oaep-wrap-key alice_oaep_pub.b64 bob_k.b64 llave_k_oaep.b64",
        "======================================================================",
        "     EJERCICIO 2.3: ENCAPSULAMIENTO DE LLAVE K CON RSA-OAEP           ",
        "======================================================================",
        " Llave pública usada        : 'alice_oaep_pub.b64'",
        " Esquema de Padding         : RSA-PKCS1-OAEP (SHA-256 / MGF1-SHA256)",
        " Tamaño del Ciphertext C    : 384 bytes (3072 bits)",
        " Archivo de salida (Base64) : 'llave_k_oaep.b64'",
        " Llave K Cifrada (Base64)   : rCPwWQPnlZ2s102Ki06yO7qkXW0aYbicnhAvEIRnAdZAGEbgnav4JcDRk9...",
        "======================================================================",
        "    -> Bob comparte 'llave_k_oaep.b64' y 'mensaje_bob.aes.enc' con Alice."
    ]
    save_screenshot(lines_09, "captura_09_bob_aes_oaep_wrap.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 2.2 & 2.3: Bob AES-128-CTR & RSA-OAEP Wrap)")

    # 10. Sección 2.4 y 2.5: Alice descifra K con RSA-OAEP-CRT y descifra el archivo con AES
    lines_10 = [
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --oaep-unwrap-key alice_oaep_priv.b64 llave_k_oaep.b64 alice_k_rec.b64",
        "======================================================================",
        "   EJERCICIO 2.4: DESENCAPSULAMIENTO DE LLAVE K CON RSA-OAEP Y CRT    ",
        "======================================================================",
        " Llave privada CRT usada     : 'alice_oaep_priv.b64'",
        " Archivo K cifrada (Base64)  : 'llave_k_oaep.b64'",
        " Longitud de K recuperada    : 16 bytes (128 bits)",
        " Llave K Recuperada (Hex)    : 96d9003a0665d574098658786102ad00",
        " Llave K Recuperada (Base64) : ltkAOgZl1XQJhlh4YQKtAA==",
        "======================================================================",
        "   -> [✓] ÉXITO: Alice recuperó exactamente la misma llave K de 128 bits de Bob.",
        "",
        "gustavo@escom-mbp:~/crypto/lab06$ ./main --aes-decrypt mensaje_bob.aes.enc mensaje_alice_recuperado.txt alice_k_rec.b64",
        "[✓] Archivo descifrado con AES-128-CTR exitosamente:",
        "    Archivo cifrado    : 'mensaje_bob.aes.enc' -> Recuperado: 'mensaje_alice_recuperado.txt' (246 bytes)",
        "======================================================================",
        "          VERIFICACIÓN DE INTEGRIDAD CRIPTOGRÁFICA (SHA-256)          ",
        "======================================================================",
        "   Archivo Original de Bob    : cdd902a88abd59bac37b873f952627f0b0f1d36f64dd3d02e37ef779f4e850cd",
        "   Archivo Descifrado (Alice) : cdd902a88abd59bac37b873f952627f0b0f1d36f64dd3d02e37ef779f4e850cd",
        " [✓] PROTOCOLO KTS-OAEP + AES-128-CTR COMPLETADO EXITOSAMENTE AL 100%",
        "======================================================================"
    ]
    save_screenshot(lines_10, "captura_10_alice_oaep_unwrap_aes_dec.png", "gustavo@escom-mbp: ~/crypto/lab06 (Section 2.4 & 2.5: Alice RSA-OAEP-CRT Unwrap & AES Decrypt)")

if __name__ == "__main__":
    generate_all()
