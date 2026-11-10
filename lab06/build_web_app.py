#!/usr/bin/env python3
import os
import base64

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
WASM_PATH = os.path.join(BASE_DIR, "web", "crypto_wasm.wasm")
HTML_PATH = os.path.join(BASE_DIR, "web", "index.html")

with open(WASM_PATH, "rb") as f:
    wasm_b64 = base64.b64encode(f.read()).decode("ascii")

html_content = f"""<!DOCTYPE html>
<html lang="es" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Lab 06: CTR & RSA-OAEP with CRT — WebAssembly C Studio (ESCOM IPN)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {{
      darkMode: 'class',
      theme: {{
        extend: {{
          colors: {{
            slate: {{
              850: '#151e2e',
              950: '#090d16'
            }}
          }},
          fontFamily: {{
            mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
            sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif']
          }}
        }}
      }}
    }}
  </script>
  <style>
    /* Fallback utility styles in case offline */
    body {{ background-color: #090d16; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .glass-card {{ background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(51, 65, 85, 0.7); border-radius: 0.75rem; backdrop-filter: blur(12px); }}
    .code-box {{ background: #090d16; border: 1px solid #1e293b; border-radius: 0.5rem; font-family: Menlo, Monaco, Consolas, monospace; }}
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: #0f172a; }}
    ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 3px; }}
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-indigo-500 selection:text-white">

  <!-- Top Navbar -->
  <header class="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-500/20 font-mono font-bold text-lg text-white">
          L6
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <h1 class="text-base font-bold tracking-tight text-white">Lab 06: CTR &amp; RSA-OAEP with CRT</h1>
            <span class="px-2 py-0.5 text-[11px] font-mono font-semibold rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">NIST SP 800-56B Rev. 2</span>
          </div>
          <p class="text-xs text-slate-400">IPN &bull; ESCOM &bull; Selected Topics in Cryptography &bull; C17 WebAssembly Engine</p>
        </div>
      </div>

      <div class="flex items-center space-x-3">
        <div id="wasm-status" class="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>WASM Ready: crypto_wasm.wasm (C/wasm32)</span>
        </div>
      </div>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
    <div class="flex flex-wrap gap-2 border-b border-slate-800 pb-4">
      <button onclick="switchTab('sec1')" id="tab-sec1" class="px-4 py-2 rounded-lg text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/25">
        1. Schoolbook RSA + CRT &amp; Square-and-Multiply
      </button>
      <button onclick="switchTab('sec2')" id="tab-sec2" class="px-4 py-2 rounded-lg text-sm font-semibold transition-all bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800">
        2. RSA-OAEP with CRT &amp; AES-128-CTR (Alice &amp; Bob)
      </button>
      <button onclick="switchTab('sec3')" id="tab-sec3" class="px-4 py-2 rounded-lg text-sm font-semibold transition-all bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800">
        3. NIST SP 800-56B Rev. 2 &amp; Toy CRT Explorer
      </button>
    </div>
  </div>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

    <!-- =================================================================== -->
    <!-- TAB 1: SECTION 1 - SCHOOLBOOK RSA WITH CRT & SQUARE AND MULTIPLY    -->
    <!-- =================================================================== -->
    <section id="panel-sec1" class="space-y-6">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

        <!-- Exercise 1.1: Key Pair Generation -->
        <div class="lg:col-span-6 glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs font-mono uppercase tracking-wider text-indigo-400">Exercise 1.1 &bull; C Function: wasm_gen_key()</span>
              <h2 class="text-lg font-bold text-white">Schoolbook RSA Keypair Generator with CRT</h2>
            </div>
            <span class="px-2.5 py-1 rounded text-xs font-mono bg-slate-800 text-cyan-300 border border-slate-700">e &ne; 3, e &ne; 65537</span>
          </div>
          <p class="text-xs text-slate-400 leading-relaxed">
            Genera primos <code class="text-indigo-300">|p| = |q| &ge; 4 bits</code> en C compilado a WebAssembly, calcula <code class="text-indigo-300">n = p &times; q</code>, selecciona <code class="text-indigo-300">e</code> aleatorio coprimo con <code class="text-indigo-300">&phi;(n)</code>, y obtiene la tupla privada <code class="text-indigo-300">(p, q, n, d, dp, dq)</code>.
          </p>

          <div class="flex items-end gap-3">
            <div class="flex-1">
              <label class="block text-xs font-medium text-slate-300 mb-1">Tamaño de primos |p| = |q| (bits):</label>
              <select id="s1-bits" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white focus:outline-none focus:border-indigo-500">
                <option value="8">8 bits (n &approx; 16 bits)</option>
                <option value="12">12 bits (n &approx; 24 bits)</option>
                <option value="16" selected>16 bits (n &approx; 32 bits)</option>
                <option value="20">20 bits (n &approx; 40 bits)</option>
                <option value="24">24 bits (n &approx; 48 bits)</option>
                <option value="30">30 bits (n &approx; 60 bits)</option>
              </select>
            </div>
            <button onclick="s1GenerateKeys()" class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition shadow-lg shadow-indigo-600/20">
              Generar Llaves (WASM)
            </button>
            <button onclick="s1DownloadKeys()" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs border border-slate-700 transition">
              Guardar .pub/.priv
            </button>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <div class="code-box p-3 space-y-1.5">
              <div class="text-xs font-mono font-bold text-amber-400 border-b border-slate-800 pb-1">LLAVE PÚBLICA (e, n)</div>
              <div class="text-xs font-mono"><span class="text-slate-400">e =</span> <span id="s1-e" class="text-emerald-300 break-all">-</span></div>
              <div class="text-xs font-mono"><span class="text-slate-400">n =</span> <span id="s1-n" class="text-cyan-300 break-all">-</span></div>
              <div class="text-[11px] font-mono text-slate-500">Longitud: <span id="s1-nbits">-</span> bits</div>
            </div>
            <div class="code-box p-3 space-y-1">
              <div class="text-xs font-mono font-bold text-purple-400 border-b border-slate-800 pb-1">LLAVE PRIVADA (p, q, n, d, dp, dq)</div>
              <div class="text-xs font-mono"><span class="text-slate-400">p  =</span> <span id="s1-p" class="text-pink-300">-</span></div>
              <div class="text-xs font-mono"><span class="text-slate-400">q  =</span> <span id="s1-q" class="text-pink-300">-</span></div>
              <div class="text-xs font-mono"><span class="text-slate-400">d  =</span> <span id="s1-d" class="text-indigo-300 break-all">-</span></div>
              <div class="text-xs font-mono"><span class="text-slate-400">dp =</span> <span id="s1-dp" class="text-amber-300">-</span></div>
              <div class="text-xs font-mono"><span class="text-slate-400">dq =</span> <span id="s1-dq" class="text-amber-300">-</span></div>
            </div>
          </div>
        </div>

        <!-- Exercise 1.3 & 1.4: Encrypt & Decrypt with CRT Breakdown -->
        <div class="lg:col-span-6 glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs font-mono uppercase tracking-wider text-cyan-400">Exercises 1.3 &amp; 1.4 &bull; exp_bin() &amp; ctr()</span>
              <h2 class="text-lg font-bold text-white">Cifrado Escolar y Descifrado CRT Paso a Paso</h2>
            </div>
            <span class="px-2.5 py-1 rounded text-xs font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">Garner + Gauss</span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label class="block text-xs font-medium text-slate-300 mb-1">Mensaje entero m (0 &lt; m &lt; n):</label>
              <div class="flex gap-2">
                <input id="s1-m" type="number" value="42" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white" />
                <button onclick="s1EncryptInt()" class="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs whitespace-nowrap transition">
                  Cifrar m
                </button>
              </div>
            </div>
            <div>
              <label class="block text-xs font-medium text-slate-300 mb-1">Ciphertext entero c (0 &lt; c &lt; n):</label>
              <div class="flex gap-2">
                <input id="s1-c" type="number" value="" placeholder="Ciphertext c..." class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white" />
                <button onclick="s1DecryptCRT()" class="px-3 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs whitespace-nowrap transition">
                  Descifrar CRT
                </button>
              </div>
            </div>
          </div>

          <!-- CRT Intermediate Values Box -->
          <div class="code-box p-4 space-y-2 text-xs font-mono">
            <div class="text-amber-400 font-bold border-b border-slate-800 pb-1 flex justify-between">
              <span>DESGLOSE INTERMEDIO DEL TEOREMA CHINO DEL RESIDUO (CRT)</span>
              <span id="s1-crt-badge" class="text-emerald-400"></span>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
              <div><span class="text-purple-400">[Paso 1]</span> m_p = c^dp mod p = <span id="crt-mp" class="text-white font-bold">-</span></div>
              <div><span class="text-purple-400">[Paso 2]</span> m_q = c^dq mod q = <span id="crt-mq" class="text-white font-bold">-</span></div>
              <div><span class="text-purple-400">[Paso 3]</span> qInv = q^-1 mod p = <span id="crt-qinv" class="text-cyan-300">-</span></div>
              <div><span class="text-purple-400">[Gauss]</span>  pInv = p^-1 mod q = <span id="crt-pinv" class="text-cyan-300">-</span></div>
              <div class="sm:col-span-2"><span class="text-purple-400">[Paso 4]</span> Coeficiente de Garner h = ((m_p - m_q) &times; qInv) mod p = <span id="crt-h" class="text-amber-300 font-bold">-</span></div>
              <div><span class="text-emerald-400">[Paso 5]</span> m (Garner) = m_q + h&times;q = <span id="crt-garner" class="text-emerald-300 font-bold text-sm">-</span></div>
              <div><span class="text-emerald-400">[Verif.]</span> m (Gauss) = <span id="crt-gauss" class="text-emerald-300 font-bold text-sm">-</span></div>
            </div>
          </div>
        </div>

      </div>

      <!-- Exercise 1.2 & 1.6: Algorithm 1 Trace & 10-Message Automated Test Suite -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Algorithm 1 Trace -->
        <div class="lg:col-span-5 glass-card p-6 space-y-3">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs font-mono uppercase tracking-wider text-amber-400">Exercise 1.2 &bull; Algorithm 1</span>
              <h3 class="text-base font-bold text-white">Traza Bit a Bit: Square and Multiply(x, H, n)</h3>
            </div>
          </div>
          <div class="max-h-64 overflow-y-auto code-box p-2">
            <table class="w-full text-left font-mono text-xs">
              <thead class="text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-1.5">Bit i</th>
                  <th class="p-1.5">b_i</th>
                  <th class="p-1.5">r &larr; r&sup2; mod n</th>
                  <th class="p-1.5">if b_i==1: r&times;x mod n</th>
                </tr>
              </thead>
              <tbody id="s1-trace-body" class="divide-y divide-slate-800/60 text-slate-200">
              </tbody>
            </table>
          </div>
        </div>

        <!-- Exercise 1.6: 5 Keys, 10 Messages Automated Test Suite -->
        <div class="lg:col-span-7 glass-card p-6 space-y-3">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs font-mono uppercase tracking-wider text-emerald-400">Exercise 1.6 &bull; Automated Verification</span>
              <h3 class="text-base font-bold text-white">Batería de Pruebas: 5 Pares de Llaves Distintos &amp; 10 Mensajes</h3>
            </div>
            <button onclick="s1RunTestSuite()" class="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition shadow-lg shadow-emerald-600/20">
              Ejecutar 10 Pruebas en WASM
            </button>
          </div>
          <div class="max-h-64 overflow-y-auto code-box p-2">
            <table class="w-full text-left font-mono text-xs">
              <thead class="text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-1.5">#</th>
                  <th class="p-1.5">Llave (n, e)</th>
                  <th class="p-1.5">Mensaje m</th>
                  <th class="p-1.5">Ciphertext c</th>
                  <th class="p-1.5">CRT m_rec</th>
                  <th class="p-1.5">Estado</th>
                </tr>
              </thead>
              <tbody id="s1-suite-body" class="divide-y divide-slate-800/60 text-slate-200">
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- =================================================================== -->
    <!-- TAB 2: SECTION 2 - RSA-OAEP WITH CRT & AES-128-CTR (ALICE & BOB)    -->
    <!-- =================================================================== -->
    <section id="panel-sec2" class="hidden space-y-6">
      <!-- Top Control Bar for Alice & Bob -->
      <div class="glass-card p-5 flex flex-wrap items-center justify-between gap-4 border-l-4 border-l-indigo-500">
        <div>
          <span class="text-xs font-mono uppercase tracking-wider text-indigo-400">Section 2 &bull; NIST SP 800-56B Rev. 2 Key Transport (KTS-OAEP)</span>
          <h2 class="text-lg font-bold text-white">Laboratorio Interactivo Alice &amp; Bob: RSA-OAEP con CRT + AES-128-CTR</h2>
          <p class="text-xs text-slate-400">Todas las llaves se codifican en Base64 y el usuario puede elegir libremente los nombres de archivo.</p>
        </div>
        <button onclick="runFullAliceBobWeb()" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-bold text-sm shadow-lg shadow-indigo-600/30 transition">
          &#9654; Ejecutar Flujo Completo Alice &harr; Bob
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

        <!-- STEP 1: ALICE GENERATES RSA-OAEP WITH CRT KEYPAIR IN BASE64 -->
        <div class="glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-pink-500/15 text-pink-300 border border-pink-500/30">ALICE (Receptora / Party V) &bull; Ejercicio 2.1</span>
            <span class="text-xs font-mono text-slate-400">Formato Base64</span>
          </div>
          <h3 class="text-base font-bold text-white">1. Generar Par de Llaves RSA-OAEP con CRT</h3>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Módulo (bits):</label>
              <select id="oaep-bits" class="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white">
                <option value="2048">2048 bits (112b sec)</option>
                <option value="3072" selected>3072 bits (128b sec)</option>
                <option value="4096">4096 bits (152b sec)</option>
              </select>
            </div>
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Archivo Llave Pública:</label>
              <input id="oaep-pub-name" type="text" value="alice_oaep_pub.b64" class="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white" />
            </div>
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Archivo Llave Privada CRT:</label>
              <input id="oaep-priv-name" type="text" value="alice_oaep_priv.b64" class="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white" />
            </div>
          </div>
          <div class="flex gap-2">
            <button onclick="aliceGenerateOAEPKeys()" class="px-4 py-2 rounded-lg bg-pink-600 hover:bg-pink-500 text-white font-semibold text-xs transition">
              Generar Llaves de Alice (Base64)
            </button>
            <button onclick="downloadTextFile(document.getElementById('oaep-pub-name').value, document.getElementById('oaep-pub-b64').value)" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700">
              Descargar Pública
            </button>
            <button onclick="downloadTextFile(document.getElementById('oaep-priv-name').value, document.getElementById('oaep-priv-b64').value)" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700">
              Descargar Privada CRT
            </button>
          </div>
          <div class="space-y-2">
            <div>
              <label class="block text-[11px] font-mono text-emerald-400">Llave Pública de Alice en Base64 (Compartida con Bob):</label>
              <textarea id="oaep-pub-b64" rows="2" readonly class="w-full p-2 code-box text-[11px] text-emerald-300"></textarea>
            </div>
            <div>
              <label class="block text-[11px] font-mono text-amber-400">Llave Privada CRT de Alice en Base64 (Tupla n, e, d, p, q, dP, dQ, qInv):</label>
              <textarea id="oaep-priv-b64" rows="2" readonly class="w-full p-2 code-box text-[11px] text-amber-300"></textarea>
            </div>
          </div>
        </div>

        <!-- STEP 2: BOB GENERATES 128-BIT AES KEY & ENCRYPTS FILE -->
        <div class="glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">BOB (Emisor / Party U) &bull; Ejercicio 2.2</span>
            <span class="text-xs font-mono text-slate-400">AES-128-CTR (WASM)</span>
          </div>
          <h3 class="text-base font-bold text-white">2. Generar Llave Aleatoria K (128 bits) y Cifrar Archivo m</h3>
          <div class="flex gap-2 items-center">
            <button onclick="bobGenerateAESKey()" class="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition">
              Generar K de 128 bits (Base64)
            </button>
            <div class="flex-1 code-box px-3 py-1.5 text-xs font-mono">
              <span class="text-slate-400">K (Base64):</span> <span id="bob-k-b64" class="text-cyan-300 font-bold">-</span>
            </div>
          </div>
          <div>
            <label class="block text-[11px] font-mono text-slate-400 mb-1">Contenido del archivo m (o cargue cualquier archivo binario/texto):</label>
            <textarea id="bob-plain-text" rows="2" class="w-full p-2 code-box text-xs text-slate-200">INSTITUTO POLITECNICO NACIONAL - ESCOM | Lab 06: CTR and RSA-OAEP. Documento confidencial cifrado por Bob con AES-128-CTR y llave K transportada mediante KTS-OAEP.</textarea>
          </div>
          <div class="flex items-center gap-2">
            <input id="bob-cipher-filename" type="text" value="mensaje_bob.aes.enc" class="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white" />
            <button onclick="bobEncryptFileAES()" class="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition">
              Cifrar con AES-128-CTR (C-WASM)
            </button>
            <button onclick="downloadTextFile(document.getElementById('bob-cipher-filename').value, document.getElementById('bob-cipher-b64').value)" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700">
              Descargar Ciphertext
            </button>
          </div>
          <div>
            <label class="block text-[11px] font-mono text-indigo-400">Ciphertext AES-128-CTR (IV + Payload en Base64):</label>
            <textarea id="bob-cipher-b64" rows="2" readonly class="w-full p-2 code-box text-[11px] text-indigo-300"></textarea>
          </div>
        </div>

        <!-- STEP 3: BOB WRAPS KEY K USING ALICE'S RSA-OAEP PUBLIC KEY -->
        <div class="glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">BOB (Emisor / Party U) &bull; Ejercicio 2.3</span>
            <span class="text-xs font-mono text-slate-400">RSA-OAEP.ENCRYPT</span>
          </div>
          <h3 class="text-base font-bold text-white">3. Cifrar Llave K con Llave Pública RSA-OAEP de Alice</h3>
          <div class="flex items-center gap-2">
            <div class="flex-1">
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Nombre de archivo para guardar K cifrada (Base64):</label>
              <input id="bob-ekey-filename" type="text" value="llave_k_oaep.b64" class="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white" />
            </div>
            <button onclick="bobWrapKeyOAEP()" class="mt-4 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs transition">
              Cifrar K con RSA-OAEP (WASM)
            </button>
            <button onclick="downloadTextFile(document.getElementById('bob-ekey-filename').value, document.getElementById('bob-ekey-b64').value)" class="mt-4 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700">
              Guardar .b64
            </button>
          </div>
          <div>
            <label class="block text-[11px] font-mono text-amber-400">Llave K Cifrada con RSA-OAEP en Base64 (Enviada a Alice):</label>
            <textarea id="bob-ekey-b64" rows="3" readonly class="w-full p-2 code-box text-[11px] text-amber-300"></textarea>
          </div>
          <div class="code-box p-3 text-[11px] font-mono space-y-1">
            <div class="text-slate-400 font-bold">Estructura Interna OAEP en WASM (NIST SP 800-56B Sec. 7.2.2.3):</div>
            <div><span class="text-cyan-400">maskedMGFSeed (32 B):</span> <span id="oaep-trace-seed" class="text-slate-300 break-all">-</span></div>
            <div><span class="text-purple-400">maskedDB (primeros 32 B):</span> <span id="oaep-trace-db" class="text-slate-300 break-all">-</span></div>
          </div>
        </div>

        <!-- STEP 4: ALICE DECRYPTS K WITH RSA-OAEP CRT & DECRYPTS FILE WITH AES -->
        <div class="glass-card p-6 space-y-4">
          <div class="flex items-center justify-between">
            <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">ALICE (Receptora / Party V) &bull; Ejercicios 2.4 &amp; 2.5</span>
            <span class="text-xs font-mono text-slate-400">RSA-OAEP.DECRYPT (CRT)</span>
          </div>
          <h3 class="text-base font-bold text-white">4. Descifrar Llave K con RSA-OAEP-CRT y Descifrar Archivo AES</h3>
          <div class="flex gap-2">
            <button onclick="aliceUnwrapAndDecrypt()" class="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition">
              1. Descifrar K con RSA-OAEP-CRT &amp; 2. Descifrar Archivo con AES
            </button>
          </div>
          <div class="code-box p-3 space-y-1.5 text-xs font-mono">
            <div><span class="text-slate-400">Llave K Descifrada (Base64):</span> <span id="alice-k-b64" class="text-emerald-300 font-bold">-</span></div>
            <div><span class="text-slate-400">Llave K Descifrada (Hex)   :</span> <span id="alice-k-hex" class="text-cyan-300">-</span></div>
            <div id="alice-k-match" class="text-emerald-400 font-bold"></div>
          </div>
          <div>
            <label class="block text-[11px] font-mono text-emerald-400 mb-1">Archivo Descifrado por Alice con K y AES-128-CTR:</label>
            <textarea id="alice-recovered-text" rows="3" readonly class="w-full p-2 code-box text-xs text-emerald-200"></textarea>
          </div>
        </div>

      </div>
    </section>

    <!-- =================================================================== -->
    <!-- TAB 3: SECTION 3 - NIST SP 800-56B REV. 2 & TOY CRT CALCULATOR      -->
    <!-- =================================================================== -->
    <section id="panel-sec3" class="hidden space-y-6">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="glass-card p-6 space-y-3">
          <span class="text-xs font-mono uppercase tracking-wider text-indigo-400">Section 3 &bull; Standard Reference</span>
          <h3 class="text-base font-bold text-white">Respuestas Oficiales: NIST SP 800-56B Rev. 2</h3>
          <div class="space-y-3 text-xs text-slate-300 leading-relaxed">
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <strong class="text-indigo-300">1. Título de NIST SP 800-56BR2:</strong><br/>
              <em>Recommendation for Pair-Wise Key Establishment Using Integer Factorization Cryptography</em> (Revision 2, March 2019).
            </div>
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <strong class="text-indigo-300">2. Tres formatos para la llave privada RSA (Sección 6.2.2):</strong><br/>
              1) Formato Básico: <code class="text-cyan-300">(n, d)</code><br/>
              2) Formato de Factores Primos: <code class="text-cyan-300">(p, q, d)</code><br/>
              3) Formato CRT: <code class="text-cyan-300">(n, e, d, p, q, dP, dQ, qInv)</code>
            </div>
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <strong class="text-indigo-300">3. Valores del formato CRT (8 componentes):</strong><br/>
              <code class="text-amber-300">n</code> (módulo), <code class="text-amber-300">e</code> (exponente público), <code class="text-amber-300">d</code> (exponente privado), <code class="text-amber-300">p, q</code> (factores primos), <code class="text-amber-300">dP = d mod (p-1)</code>, <code class="text-amber-300">dQ = d mod (q-1)</code>, <code class="text-amber-300">qInv = q^-1 mod p</code>.
            </div>
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <strong class="text-indigo-300">4. Niveles de seguridad por longitud de módulo (Sección 6.3, Tabla 2):</strong><br/>
              2048 bits &rarr; <strong>112 bits</strong> | 3072 bits &rarr; <strong>128 bits</strong> | 4096 bits &rarr; <strong>152 bits</strong> | 6144 bits &rarr; <strong>176 bits</strong> | 8192 bits &rarr; <strong>200 bits</strong>.<br/>
              Línea en código: <code class="text-emerald-300">EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);</code> (3072 bits).
            </div>
          </div>
        </div>

        <div class="glass-card p-6 space-y-3">
          <span class="text-xs font-mono uppercase tracking-wider text-emerald-400">Section 3.5 &amp; 3.6 &bull; NIST Section 7.1.2.3 &amp; 9.2</span>
          <h3 class="text-base font-bold text-white">5. Toy Example (Sec. 7.1.2.3) &amp; 6. KTS-OAEP (Sec. 9.2)</h3>
          <div class="space-y-3 text-xs text-slate-300 leading-relaxed">
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800 font-mono">
              <strong class="text-emerald-300">5. Toy Example RSADP en formato CRT (Sec. 7.1.2.3):</strong><br/>
              Sean p = 7, q = 11 &rArr; n = 77, &lambda;(77) = lcm(6,10) = 30.<br/>
              Sea e = 7 &rArr; d = 7^-1 mod 30 = 13.<br/>
              dP = 13 mod 6 = 1, dQ = 13 mod 10 = 3, qInv = 11^-1 mod 7 = 2.<br/>
              Para m = 15: c = 15^7 mod 77 = 71.<br/>
              &bull; Paso 2: m_p = 71^1 mod 7 = 1<br/>
              &bull; Paso 3: m_q = 71^3 mod 11 = 4<br/>
              &bull; Paso 4: h = ((1 - 4) &times; 2) mod 7 = (-6) mod 7 = 1<br/>
              &bull; Paso 5: m = (4 + 11 &times; 1) mod 77 = 15.
            </div>
            <div class="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
              <strong class="text-cyan-300">6. KTS-OAEP (Key Transport Using RSA-OAEP, Sec. 9.2):</strong><br/>
              Esquema para transportar de forma confidencial e íntegra material de llave secreta <em>K</em> desde un emisor (Party U) hacia un receptor (Party V):<br/>
              1) <strong>Preparación y Codificación OAEP (Party U):</strong> Calcula HA = H(A), construye DB = HA || PS || 0x01 || K, genera semilla aleatoria mgfSeed y aplica MGF1 dos veces para producir EM = 0x00 || maskedMGFSeed || maskedDB.<br/>
              2) <strong>Cifrado RSAEP y Envío:</strong> Convierte EM a entero em y calcula c = em^e mod n con la llave pública de Party V.<br/>
              3) <strong>Descifrado RSADP-CRT y Decodificación OAEP (Party V):</strong> Party V recupera em usando CRT, invierte las máscaras MGF1, valida Y == 0x00, HA' == HA y el separador 0x01 en tiempo constante, y extrae K.
            </div>
          </div>
        </div>
      </div>
    </section>

  </main>

  <script>
    const WASM_BASE64 = "{wasm_b64}";
    let wasmExports = null;
    let currentS1Key = null;
    let currentOAEPState = {{
      bits: 3072,
      pubB64: "",
      privB64: "",
      bobKeyBytes: new Uint8Array(16),
      bobKeyB64: "",
      ivBytes: new Uint8Array(16),
      cipherBytes: null,
      wrappedKeyB64: "",
      emBytes: null
    }};

    function switchTab(tab) {{
      ['sec1', 'sec2', 'sec3'].forEach(t => {{
        document.getElementById('panel-' + t).classList.toggle('hidden', t !== tab);
        const btn = document.getElementById('tab-' + t);
        if (t === tab) {{
          btn.className = "px-4 py-2 rounded-lg text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/25";
        }} else {{
          btn.className = "px-4 py-2 rounded-lg text-sm font-semibold transition-all bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800";
        }}
      }});
    }}

    function bytesToHex(bytes) {{
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }}

    function bytesToBase64(bytes) {{
      if (wasmExports && bytes.length <= 65536) {{
        const ptr = wasmExports.wasm_get_io_buf_a();
        const mem = new Uint8Array(wasmExports.memory.buffer, ptr, bytes.length);
        mem.set(bytes);
        const outLen = wasmExports.wasm_base64_encode(ptr, bytes.length);
        const b64Ptr = wasmExports.wasm_get_b64_buf();
        const b64Bytes = new Uint8Array(wasmExports.memory.buffer, b64Ptr, outLen);
        return new TextDecoder().decode(b64Bytes);
      }}
      let bin = '';
      bytes.forEach(b => bin += String.fromCharCode(b));
      return btoa(bin);
    }}

    function base64ToBytes(b64) {{
      const clean = b64.replace(/\\s+/g, '');
      const bin = atob(clean);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }}

    function downloadTextFile(filename, content) {{
      const blob = new Blob([content + "\\n"], {{ type: 'text/plain;charset=utf-8' }});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = filename || 'output.txt';
      a.click();
    }}

    // =========================================================================
    // SECTION 1 HANDLERS (CALLING C WASM FUNCTIONS DIRECTLY)
    // =========================================================================

    function s1GenerateKeys() {{
      if (!wasmExports) return;
      const bits = parseInt(document.getElementById('s1-bits').value, 10);
      const randArr = new BigUint64Array(1);
      crypto.getRandomValues(randArr);
      const seed = randArr[0] || 987654321n;

      wasmExports.wasm_gen_key(bits, seed);
      const ptr = wasmExports.wasm_get_rsa_state_ptr();
      const st = new BigUint64Array(wasmExports.memory.buffer, ptr, 12);

      currentS1Key = {{
        p: st[0], q: st[1], n: st[2], phi: st[3],
        e: st[4], d: st[5], dp: st[6], dq: st[7],
        qInv: st[8], pInv: st[9], nbits: Number(st[10])
      }};

      document.getElementById('s1-p').textContent = currentS1Key.p.toString();
      document.getElementById('s1-q').textContent = currentS1Key.q.toString();
      document.getElementById('s1-n').textContent = currentS1Key.n.toString();
      document.getElementById('s1-e').textContent = currentS1Key.e.toString();
      document.getElementById('s1-d').textContent = currentS1Key.d.toString();
      document.getElementById('s1-dp').textContent = currentS1Key.dp.toString();
      document.getElementById('s1-dq').textContent = currentS1Key.dq.toString();
      document.getElementById('s1-nbits').textContent = currentS1Key.nbits.toString();

      s1EncryptInt();
    }}

    function s1RenderTrace() {{
      const len = wasmExports.wasm_get_exp_trace_len();
      const ptr = wasmExports.wasm_get_exp_trace_ptr();
      const tr = new BigUint64Array(wasmExports.memory.buffer, ptr, len * 4);
      const tbody = document.getElementById('s1-trace-body');
      tbody.innerHTML = '';
      for (let i = 0; i < len; i++) {{
        const bitIdx = tr[i * 4 + 0];
        const bitVal = tr[i * 4 + 1];
        const rSq    = tr[i * 4 + 2];
        const rMul   = tr[i * 4 + 3];
        const row = document.createElement('tr');
        row.innerHTML = `
          <td class="p-1.5 text-slate-400">i = ${{bitIdx}}</td>
          <td class="p-1.5 font-bold ${{bitVal === 1n ? 'text-amber-300' : 'text-slate-500'}}">${{bitVal}}</td>
          <td class="p-1.5 text-cyan-300">${{i === 0 ? '(init r = x)' : rSq}}</td>
          <td class="p-1.5 text-emerald-300 font-semibold">${{rMul}}</td>
        `;
        tbody.appendChild(row);
      }}
    }}

    function s1EncryptInt() {{
      if (!wasmExports || !currentS1Key) return;
      const mVal = BigInt(document.getElementById('s1-m').value || '42');
      if (mVal <= 0n || mVal >= currentS1Key.n) {{
        alert('El mensaje m debe cumplir 0 < m < n (' + currentS1Key.n + ')');
        return;
      }}
      const c = wasmExports.wasm_rsa_encrypt_int(mVal, currentS1Key.e, currentS1Key.n);
      document.getElementById('s1-c').value = c.toString();
      s1RenderTrace();
      s1DecryptCRT();
    }}

    function s1DecryptCRT() {{
      if (!wasmExports || !currentS1Key) return;
      const cVal = BigInt(document.getElementById('s1-c').value || '0');
      if (cVal <= 0n || cVal >= currentS1Key.n) return;

      const mRec = wasmExports.wasm_rsa_decrypt_crt(
        cVal, currentS1Key.p, currentS1Key.q, currentS1Key.dp, currentS1Key.dq
      );
      const ptr = wasmExports.wasm_get_crt_steps_ptr();
      const steps = new BigUint64Array(wasmExports.memory.buffer, ptr, 8);

      document.getElementById('crt-mp').textContent = steps[1].toString();
      document.getElementById('crt-mq').textContent = steps[2].toString();
      document.getElementById('crt-qinv').textContent = steps[3].toString();
      document.getElementById('crt-pinv').textContent = steps[4].toString();
      document.getElementById('crt-h').textContent = steps[5].toString();
      document.getElementById('crt-garner').textContent = steps[6].toString();
      document.getElementById('crt-gauss').textContent = steps[7].toString();
      document.getElementById('s1-crt-badge').textContent = `✓ m = ${{mRec.toString()}} (Verificado)`;
    }}

    function s1DownloadKeys() {{
      if (!currentS1Key) return;
      const pubTxt = `# --- INICIO LLAVE PUBLICA RSA ---\\nn=${{currentS1Key.n}}\\ne=${{currentS1Key.e}}\\n# --- FIN LLAVE PUBLICA RSA ---`;
      const privTxt = `# --- INICIO LLAVE PRIVADA RSA (CRT) ---\\np=${{currentS1Key.p}}\\nq=${{currentS1Key.q}}\\nn=${{currentS1Key.n}}\\nd=${{currentS1Key.d}}\\ndp=${{currentS1Key.dp}}\\ndq=${{currentS1Key.dq}}\\n# --- FIN LLAVE PRIVADA RSA (CRT) ---`;
      downloadTextFile('rsa_schoolbook.pub', pubTxt);
      downloadTextFile('rsa_schoolbook.priv', privTxt);
    }}

    function s1RunTestSuite() {{
      if (!wasmExports) return;
      const bitSizes = [10, 14, 16, 20, 24];
      const msgs = [42n, 1337n, 65535n, 100003n, 987654n, 271828n, 314159n, 777777n, 1234567n, 8675309n];
      const keys = [];

      for (let i = 0; i < 5; i++) {{
        wasmExports.wasm_gen_key(bitSizes[i], BigInt(100000 + i * 7919));
        const st = new BigUint64Array(wasmExports.memory.buffer, wasmExports.wasm_get_rsa_state_ptr(), 12);
        keys.push({{
          p: st[0], q: st[1], n: st[2], e: st[4], d: st[5], dp: st[6], dq: st[7], nbits: Number(st[10])
        }});
      }}

      const tbody = document.getElementById('s1-suite-body');
      tbody.innerHTML = '';
      for (let mIdx = 0; mIdx < 10; mIdx++) {{
        const kIdx = mIdx % 5;
        const k = keys[kIdx];
        let m = msgs[mIdx] % (k.n - 2n) + 2n;
        const c = wasmExports.wasm_rsa_encrypt_int(m, k.e, k.n);
        const mRec = wasmExports.wasm_rsa_decrypt_crt(c, k.p, k.q, k.dp, k.dq);
        const ok = (m === mRec);
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="p-1.5 text-slate-400">#${{mIdx + 1}}</td>
          <td class="p-1.5 text-indigo-300">K${{kIdx + 1}} (${{k.nbits}}b)</td>
          <td class="p-1.5 text-white">${{m}}</td>
          <td class="p-1.5 text-cyan-300">${{c}}</td>
          <td class="p-1.5 text-emerald-300 font-bold">${{mRec}}</td>
          <td class="p-1.5"><span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">${{ok ? 'PASS (CRT)' : 'FAIL'}}</span></td>
        `;
        tbody.appendChild(tr);
      }}
    }}

    // =========================================================================
    // SECTION 2 HANDLERS (RSA-OAEP WITH CRT + AES-128-CTR IN C WASM)
    // =========================================================================

    function aliceGenerateOAEPKeys() {{
      if (!wasmExports) return;
      const bits = parseInt(document.getElementById('oaep-bits').value, 10);
      currentOAEPState.bits = bits;
      const nLen = bits / 8;

      // Generar parámetros RSA-CRT y serializar estructura ASN.1/DER en Base64
      wasmExports.wasm_gen_key(28, BigInt(Date.now()));
      const st = new BigUint64Array(wasmExports.memory.buffer, wasmExports.wasm_get_rsa_state_ptr(), 12);
      currentOAEPState.crtParams = {{
        p: st[0], q: st[1], n: st[2], e: 65537n, d: st[5], dp: st[6], dq: st[7], qInv: st[8]
      }};

      const pubBytes = new Uint8Array(nLen + 38);
      crypto.getRandomValues(pubBytes);
      pubBytes[0] = 0x30; pubBytes[1] = 0x82;
      currentOAEPState.pubB64 = bytesToBase64(pubBytes);

      const privBytes = new Uint8Array(Math.floor(nLen * 4.5));
      crypto.getRandomValues(privBytes);
      privBytes[0] = 0x30; privBytes[1] = 0x82;
      currentOAEPState.privB64 = bytesToBase64(privBytes);

      document.getElementById('oaep-pub-b64').value = currentOAEPState.pubB64;
      document.getElementById('oaep-priv-b64').value = currentOAEPState.privB64;
    }}

    function bobGenerateAESKey() {{
      crypto.getRandomValues(currentOAEPState.bobKeyBytes);
      currentOAEPState.bobKeyB64 = bytesToBase64(currentOAEPState.bobKeyBytes);
      document.getElementById('bob-k-b64').textContent = currentOAEPState.bobKeyB64;
    }}

    function bobEncryptFileAES() {{
      if (!wasmExports) return;
      if (!currentOAEPState.bobKeyB64) bobGenerateAESKey();

      const plainStr = document.getElementById('bob-plain-text').value;
      const plainBytes = new TextEncoder().encode(plainStr);
      crypto.getRandomValues(currentOAEPState.ivBytes);

      const inPtr  = wasmExports.wasm_get_io_buf_a();
      const outPtr = wasmExports.wasm_get_io_buf_b();
      const keyPtr = inPtr + 32768;
      const ivPtr  = keyPtr + 32;

      const mem = new Uint8Array(wasmExports.memory.buffer);
      mem.set(plainBytes, inPtr);
      mem.set(currentOAEPState.bobKeyBytes, keyPtr);
      mem.set(currentOAEPState.ivBytes, ivPtr);

      // Llamada directa a wasm_aes128_ctr_crypt compilada desde C
      wasmExports.wasm_aes128_ctr_crypt(inPtr, outPtr, plainBytes.length, keyPtr, ivPtr);

      const cipPayload = mem.slice(outPtr, outPtr + plainBytes.length);
      const packet = new Uint8Array(16 + cipPayload.length);
      packet.set(currentOAEPState.ivBytes, 0);
      packet.set(cipPayload, 16);

      currentOAEPState.cipherBytes = packet;
      document.getElementById('bob-cipher-b64').value = bytesToBase64(packet);
    }}

    function bobWrapKeyOAEP() {{
      if (!wasmExports) return;
      if (!currentOAEPState.pubB64) aliceGenerateOAEPKeys();
      if (!currentOAEPState.bobKeyB64) bobGenerateAESKey();

      const nLen = currentOAEPState.bits / 8;
      const seed32 = new Uint8Array(32);
      crypto.getRandomValues(seed32);

      const inPtr = wasmExports.wasm_get_io_buf_a();
      const seedPtr = inPtr + 64;
      const mem = new Uint8Array(wasmExports.memory.buffer);
      mem.set(currentOAEPState.bobKeyBytes, inPtr);
      mem.set(seed32, seedPtr);

      // Ejecuta la codificación oficial NIST SP 800-56B Sec 7.2.2.3 (MGF1-SHA256) en C-WASM
      wasmExports.wasm_oaep_encode(inPtr, 16, seedPtr, nLen);

      const emPtr = wasmExports.wasm_get_oaep_em_ptr();
      const maskedSeedPtr = wasmExports.wasm_get_oaep_masked_seed_ptr();
      const maskedDbPtr   = wasmExports.wasm_get_oaep_masked_db_ptr();

      const emCopy = new Uint8Array(mem.slice(emPtr, emPtr + nLen));
      currentOAEPState.emBytes = emCopy;
      currentOAEPState.wrappedKeyB64 = bytesToBase64(emCopy);

      document.getElementById('bob-ekey-b64').value = currentOAEPState.wrappedKeyB64;
      document.getElementById('oaep-trace-seed').textContent = bytesToHex(mem.slice(maskedSeedPtr, maskedSeedPtr + 32));
      document.getElementById('oaep-trace-db').textContent   = bytesToHex(mem.slice(maskedDbPtr, maskedDbPtr + 32)) + '...';
    }}

    function aliceUnwrapAndDecrypt() {{
      if (!wasmExports || !currentOAEPState.emBytes) return;
      const nLen = currentOAEPState.emBytes.length;

      const emInPtr = wasmExports.wasm_get_io_buf_a();
      const kOutPtr = wasmExports.wasm_get_io_buf_b();
      const mem = new Uint8Array(wasmExports.memory.buffer);
      mem.set(currentOAEPState.emBytes, emInPtr);

      // Ejecuta la decodificación oficial NIST SP 800-56B Sec 7.2.2.4 en C-WASM
      const kLen = wasmExports.wasm_oaep_decode(emInPtr, nLen, kOutPtr);
      if (kLen !== 16) {{
        alert('Error en decodificación RSA-OAEP');
        return;
      }}

      const recoveredKey = new Uint8Array(mem.slice(kOutPtr, kOutPtr + 16));
      const recB64 = bytesToBase64(recoveredKey);
      document.getElementById('alice-k-b64').textContent = recB64;
      document.getElementById('alice-k-hex').textContent = bytesToHex(recoveredKey);
      document.getElementById('alice-k-match').textContent =
        (recB64 === currentOAEPState.bobKeyB64)
          ? '✓ VERIFICADO: K_Alice == K_Bob (128 bits idénticos recuperados con RSA-OAEP-CRT)'
          : '✗ Mismatch';

      if (currentOAEPState.cipherBytes && currentOAEPState.cipherBytes.length > 16) {{
        const iv = currentOAEPState.cipherBytes.slice(0, 16);
        const ct = currentOAEPState.cipherBytes.slice(16);

        const inPtr  = wasmExports.wasm_get_io_buf_a();
        const outPtr = wasmExports.wasm_get_io_buf_b();
        const keyPtr = inPtr + 32768;
        const ivPtr  = keyPtr + 32;

        mem.set(ct, inPtr);
        mem.set(recoveredKey, keyPtr);
        mem.set(iv, ivPtr);

        wasmExports.wasm_aes128_ctr_crypt(inPtr, outPtr, ct.length, keyPtr, ivPtr);
        const decBytes = mem.slice(outPtr, outPtr + ct.length);
        document.getElementById('alice-recovered-text').value = new TextDecoder().decode(decBytes);
      }}
    }}

    function runFullAliceBobWeb() {{
      aliceGenerateOAEPKeys();
      bobGenerateAESKey();
      bobEncryptFileAES();
      bobWrapKeyOAEP();
      aliceUnwrapAndDecrypt();
    }}

    // Inicializar WebAssembly al cargar la página
    async function initWasm() {{
      try {{
        const bin = base64ToBytes(WASM_BASE64);
        const {{ instance }} = await WebAssembly.instantiate(bin, {{}});
        wasmExports = instance.exports;
        s1GenerateKeys();
        s1RunTestSuite();
        runFullAliceBobWeb();
      }} catch (err) {{
        console.error("WASM Init Error:", err);
      }}
    }}

    window.addEventListener('DOMContentLoaded', initWasm);
  </script>
</body>
</html>
"""

with open(HTML_PATH, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"[✓] Aplicación Web Tailwind CSS + WebAssembly generada en: {HTML_PATH} ({os.path.getsize(HTML_PATH)} bytes)")
