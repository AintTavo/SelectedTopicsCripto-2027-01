import zipfile
import html

def build_docx(filename, doc_title, sections, lang_code="es"):
    # Content Types
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

    # Top-level rels
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

    # Word rels
    word_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

    # Styles definition
    styles_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>
        <w:sz w:val="22"/>
        <w:color w:val="2D3748"/>
      </w:rPr>
    </w:rPrDefault>
    <w:pPrDefault>
      <w:pPr>
        <w:spacing w:line="276" w:lineRule="auto" w:after="160"/>
      </w:pPr>
    </w:pPrDefault>
  </w:docDefaults>
</w:styles>"""

    # Document body construction
    body_parts = []

    def p_title(text):
        return f"""<w:p>
          <w:pPr>
            <w:spacing w:before="200" w:after="80"/>
            <w:jc w:val="center"/>
          </w:pPr>
          <w:r>
            <w:rPr>
              <w:b/>
              <w:sz w:val="38"/>
              <w:color w:val="1A365D"/>
            </w:rPr>
            <w:t>{html.escape(text)}</w:t>
          </w:r>
        </w:p>"""

    def p_subtitle(text):
        return f"""<w:p>
          <w:pPr>
            <w:spacing w:before="0" w:after="300"/>
            <w:jc w:val="center"/>
          </w:pPr>
          <w:r>
            <w:rPr>
              <w:i/>
              <w:sz w:val="22"/>
              <w:color w:val="4A5568"/>
            </w:rPr>
            <w:t>{html.escape(text)}</w:t>
          </w:r>
        </w:p>"""

    def p_meta(label, val):
        return f"""<w:p>
          <w:pPr><w:spacing w:after="60"/></w:pPr>
          <w:r><w:rPr><w:b/><w:color w:val="2B6CB0"/></w:rPr><w:t>{html.escape(label)}: </w:t></w:r>
          <w:r><w:t>{html.escape(val)}</w:t></w:r>
        </w:p>"""

    def p_h1(text):
        return f"""<w:p>
          <w:pPr>
            <w:spacing w:before="360" w:after="120"/>
            <w:pBdr>
              <w:bottom w:val="single" w:sz="12" w:space="4" w:color="2B6CB0"/>
            </w:pBdr>
          </w:pPr>
          <w:r>
            <w:rPr>
              <w:b/>
              <w:sz w:val="28"/>
              <w:color w:val="1A365D"/>
            </w:rPr>
            <w:t>{html.escape(text)}</w:t>
          </w:r>
        </w:p>"""

    def p_h2(text):
        return f"""<w:p>
          <w:pPr><w:spacing w:before="240" w:after="80"/></w:pPr>
          <w:r>
            <w:rPr>
              <w:b/>
              <w:sz w:val="24"/>
              <w:color w:val="2B6CB0"/>
            </w:rPr>
            <w:t>{html.escape(text)}</w:t>
          </w:r>
        </w:p>"""

    def p_body(text, bold_prefix=None):
        runs = ""
        if bold_prefix:
            runs += f"""<w:r><w:rPr><w:b/><w:color w:val="1A202C"/></w:rPr><w:t>{html.escape(bold_prefix)} </w:t></w:r>"""
        runs += f"""<w:r><w:t>{html.escape(text)}</w:t></w:r>"""
        return f"""<w:p><w:pPr><w:spacing w:after="120"/></w:pPr>{runs}</w:p>"""

    def p_bullet(text, bold_title=None):
        runs = ""
        if bold_title:
            runs += f"""<w:r><w:rPr><w:b/><w:color w:val="2B6CB0"/></w:rPr><w:t>{html.escape(bold_title)} </w:t></w:r>"""
        runs += f"""<w:r><w:t>{html.escape(text)}</w:t></w:r>"""
        return f"""<w:p>
          <w:pPr>
            <w:ind w:left="400" w:hanging="240"/>
            <w:spacing w:after="80"/>
          </w:pPr>
          <w:r><w:t>•   </w:t></w:r>
          {runs}
        </w:p>"""

    def p_formula(eq_text, label=None):
        lbl_part = ""
        if label:
            lbl_part = f"""<w:r><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="718096"/></w:rPr><w:t>{html.escape(label)}: </w:t></w:r><w:br/>"""
        return f"""<w:p>
          <w:pPr>
            <w:pBdr>
              <w:left w:val="single" w:sz="24" w:space="15" w:color="3182CE"/>
            </w:pBdr>
            <w:shd w:val="clear" w:color="auto" w:fill="F7FAFC"/>
            <w:ind w:left="300" w:right="200"/>
            <w:spacing w:before="120" w:after="120"/>
          </w:pPr>
          {lbl_part}
          <w:r>
            <w:rPr>
              <w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>
              <w:b/>
              <w:sz w:val="22"/>
              <w:color w:val="1A365D"/>
            </w:rPr>
            <w:t>{html.escape(eq_text)}</w:t>
          </w:r>
        </w:p>"""

    # Build Header
    body_parts.append(p_title(doc_title))
    if lang_code == "es":
        body_parts.append(p_subtitle("Instituto Politécnico Nacional — Escuela Superior de Cómputo (ESCOM)\nTemas Selectos de Criptografía — Laboratorio 01"))
        body_parts.append(p_meta("Materia", "Temas Selectos de Criptografía"))
        body_parts.append(p_meta("Práctica", "Laboratorio 01: Curvas Elípticas y Aritmética Modular con Enteros Grandes (GMP)"))
        body_parts.append(p_meta("Contenido del Documento", "Explicación teórica y matemática de los algoritmos implementados (sin código fuente)"))
    else:
        body_parts.append(p_subtitle("Instituto Politécnico Nacional — Escuela Superior de Cómputo (ESCOM)\nSelected Topics in Cryptography — Lab 01"))
        body_parts.append(p_meta("Course", "Selected Topics in Cryptography"))
        body_parts.append(p_meta("Session", "Lab 01: Elliptic Curves and Modular Arithmetic with Big Integers (GMP)"))
        body_parts.append(p_meta("Document Content", "Theoretical and mathematical explanations of the implemented algorithms (no source code)"))

    # Iterate sections
    for sec in sections:
        if sec["type"] == "h1":
            body_parts.append(p_h1(sec["text"]))
        elif sec["type"] == "h2":
            body_parts.append(p_h2(sec["text"]))
        elif sec["type"] == "body":
            body_parts.append(p_body(sec["text"], sec.get("bold")))
        elif sec["type"] == "bullet":
            body_parts.append(p_bullet(sec["text"], sec.get("bold")))
        elif sec["type"] == "formula":
            body_parts.append(p_formula(sec["text"], sec.get("label")))

    # Page setup (margins: top 1440, bottom 1440, left 1440, right 1440 = 1 inch)
    sect_pr = """<w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>"""

    doc_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    {''.join(body_parts)}
    {sect_pr}
  </w:body>
</w:document>"""

    with zipfile.ZipFile(filename, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/_rels/document.xml.rels", word_rels)
        z.writestr("word/styles.xml", styles_xml)
        z.writestr("word/document.xml", doc_xml.encode("utf-8"))

    print(f"Generated successfully: {filename}")

# =========================================================================
# SECCIONES EN ESPAÑOL
# =========================================================================
sections_es = [
    {"type": "h1", "text": "1. Sección 1: Funciones Preliminares"},

    {"type": "h2", "text": "Algoritmo 1.1: Residuos Cuadráticos y Raíces Módulo p > 3"},
    {"type": "body", "text": "Este algoritmo calcula el conjunto de todos los residuos cuadráticos QR_p en el campo finito Z_p y extrae de forma exacta las dos raíces cuadradas asociadas a cada residuo."},
    {"type": "bullet", "bold": "Fundamento Matemático:", "text": "En cualquier campo finito primo Z_p con p > 2, existen exactamente (p - 1) / 2 residuos cuadráticos no nulos, más el residuo trivial 0, totalizando exactamente ((p - 1) / 2) + 1 residuos cuadráticos."},
    {"type": "bullet", "bold": "Reducción de Complejidad a O(p):", "text": "En lugar de realizar una búsqueda cuadrática evaluando cada residuo candidato r en [0, p-1] contra todo posible candidato a raíz (complejidad O(p²)), el algoritmo recorre directamente el rango de raíces y en [0, (p - 1) / 2] y calcula de forma directa r ≡ y² (mod p)."},
    {"type": "formula", "label": "Generación de Residuo", "text": "r ≡ y² (mod p)    donde y ∈ [0, (p - 1) / 2]"},
    {"type": "bullet", "bold": "Determinación de Raíces Cuadradas:", "text": "Por congruencias modulares, si y² ≡ r (mod p), se cumple que (-y)² ≡ (p - y)² ≡ r (mod p). Por consiguiente: para y = 0 se obtiene una única raíz {0}; para cada y > 0 se obtienen exactamente dos raíces simétricas {y, p - y}."},
    {"type": "formula", "label": "Par de Raíces Cuadradas", "text": "Raíces(r) = { y,  p - y }    en Z_p  (para todo r > 0)"},
    {"type": "bullet", "bold": "Búsqueda en O(1) con Tabla Hash Indexada:", "text": "Los residuos se almacenan indexados directamente por su valor numérico en una tabla de cubetas. Esto permite que el posterior conteo de puntos en curvas elípticas consulte la existencia de una raíz en tiempo constante O(1) sin necesidad de recalcular exponenciaciones modulares."},

    {"type": "h2", "text": "Algoritmo 1.2: Búsqueda y Conteo de Puntos Racionales de una Curva Elíptica"},
    {"type": "body", "text": "Determina todos los pares ordenados (x, y) que satisfacen la ecuación de Weierstraß en el campo finito Z_p, incorporando el punto al infinito en coordenadas de 3 dimensiones y exportando los resultados a un archivo CSV."},
    {"type": "bullet", "bold": "Validación de No Singularidad:", "text": "Antes de computar puntos, el algoritmo calcula el discriminante discreto Δ de la curva. Si Δ ≡ 0 (mod p), la curva presenta singularidades (puntos de cúspide o auto-intersección) y carece de estructura de grupo algebraico abeliano; el algoritmo la rechaza de inmediato."},
    {"type": "formula", "label": "Discriminante de la Curva", "text": "Δ ≡ 4a³ + 27b² (mod p)    [Condición requerida: Δ ≠ 0 (mod p)]"},
    {"type": "bullet", "bold": "Inclusión del Elemento Neutro:", "text": "De acuerdo con la formulación proyectiva requerida, el punto al infinito 𝒪 se almacena como el primer elemento del grupo con coordenadas fijas (0, 1, 0), es decir, con z = 0."},
    {"type": "formula", "label": "Punto al Infinito", "text": "𝒪 = (0, 1, 0)    con z = 0"},
    {"type": "bullet", "bold": "Evaluación de Puntos Afines en O(p):", "text": "Para cada abscisa candidata x en [0, p-1], se evalúa el polinomio cúbico lado_derecho = x³ + ax + b (mod p). Empleando la tabla de residuos cuadráticos en O(1), si lado_derecho es un residuo cuadrático, se extraen sus dos raíces asociadas y, construyendo los puntos afines (x, y, 1) con z = 1."},
    {"type": "formula", "label": "Ecuación de la Curva Elíptica", "text": "y² ≡ x³ + ax + b (mod p)"},
    {"type": "bullet", "bold": "Exportación CSV Estructurada:", "text": "Los metadatos de la curva (p, a, b, conteo) y las ternas (x, y, z) se escriben en un archivo de texto con encabezados estandarizados para su posterior análisis o graficación."},

    {"type": "h1", "text": "2. Sección 2: Aritmética de Curvas Elípticas con Enteros Grandes (GMP)"},

    {"type": "h2", "text": "Algoritmo 2.1: Generación de Curvas Elípticas No Singulares de n Bits"},
    {"type": "body", "text": "Genera de manera aleatoria un número primo p de longitud en bits arbitraria (desde 16 hasta 2048 bits) y selecciona coeficientes a, b en Z_p que garanticen una curva suave y apta para criptografía."},
    {"type": "bullet", "bold": "Generación de Primo de n Bits Exactos:", "text": "Genera un número pseudoaleatorio uniforme de n bits con mpz_urandomb. Fuerza el bit más significativo (bit n-1) en 1 para fijar el rango en [2^(n-1), 2^n - 1] y el bit menos significativo en 1 para garantizar imparidad. Aplica la función mpz_nextprime (que ejecuta rondas de Miller-Rabin) para localizar el siguiente primo probable."},
    {"type": "formula", "label": "Rango del Primo de n Bits", "text": "p ∈ [ 2^(n-1),  2^n - 1 ]    donde p es primo y p > 3"},
    {"type": "bullet", "bold": "Selección de Parámetros No Singulares:", "text": "Elige a, b aleatoriamente en el intervalo [0, p-1] mediante mpz_urandomm. Verifica que 4a³ + 27b² ≢ 0 (mod p). Dado que la probabilidad de colisión singular sobre un campo grande es ~1/p, el algoritmo converge de forma instantánea (menos de 0.06 s para 2048 bits)."},

    {"type": "h2", "text": "Algoritmo 2.2: Suma de Puntos Distintos P + Q (donde P ≠ ±Q)"},
    {"type": "body", "text": "Calcula la suma geométrica-algebraica de dos puntos sobre la curva elíptica utilizando la ley de adición en coordenadas afines con soporte proyectivo en 3 coordenadas."},
    {"type": "bullet", "bold": "Verificación de Pertenencia:", "text": "Antes de cualquier operación, se evalúa si y² ≡ x³ + ax + b (mod p) para ambos puntos. Si alguno no pertenece a la curva, la función aborta con un mensaje de error explícito."},
    {"type": "bullet", "bold": "Manejo de Casos Especiales de Grupo:", "text": "Si P = 𝒪, el resultado es Q. Si Q = 𝒪, el resultado es P. Si x_P = x_Q y y_P ≡ -y_Q (mod p), la recta secante es vertical y el resultado es el punto al infinito 𝒪 = (0, 1, 0)."},
    {"type": "bullet", "bold": "Cálculo de la Pendiente Secante (λ):", "text": "La recta que pasa por P y Q tiene pendiente λ = (y₂ - y₁) / (x₂ - x₁) (mod p). El inverso modular del denominador se obtiene mediante el algoritmo de Euclides extendido (mpz_invert)."},
    {"type": "formula", "label": "Pendiente de la Secante", "text": "λ ≡ (y₂ - y₁) · (x₂ - x₁)⁻¹ (mod p)"},
    {"type": "bullet", "bold": "Coordenadas del Punto Resultante R = (x₃, y₃, 1):", "text": "Sustituyendo la recta secante en la ecuación cúbica y aplicando las fórmulas de Viète para las raíces del polinomio:"},
    {"type": "formula", "label": "Abscisa Resultante", "text": "x₃ ≡ λ² - x₁ - x₂ (mod p)"},
    {"type": "formula", "label": "Ordenada Resultante", "text": "y₃ ≡ λ · (x₁ - x₃) - y₁ (mod p)"},

    {"type": "h2", "text": "Algoritmo 2.3: Duplicación de Punto 2P"},
    {"type": "body", "text": "Calcula la adición de un punto consigo mismo (P + P) trazando la recta tangente a la curva elíptica en el punto P."},
    {"type": "bullet", "bold": "Derivación Implícita de la Pendiente Tangente:", "text": "Diferenciando la ecuación de la curva 2y(dy/dx) = 3x² + a, la pendiente de la recta tangente en P = (x₁, y₁) está dada por:"},
    {"type": "formula", "label": "Pendiente de la Tangente", "text": "λ ≡ (3x₁² + a) · (2y₁)⁻¹ (mod p)"},
    {"type": "bullet", "bold": "Tangente Vertical:", "text": "Si y₁ ≡ 0 (mod p), el denominador es divisible entre p (no existe inverso multiplicativo modular). Geométricamente, la tangente es perfectamente vertical y converge en el punto al infinito: 2P = 𝒪 = (0, 1, 0)."},
    {"type": "bullet", "bold": "Coordenadas del Punto Duplicado R = 2P:", "text": "Intersectando la recta tangente con la curva cúbica se obtienen las coordenadas:"},
    {"type": "formula", "label": "Abscisa Duplicada", "text": "x₃ ≡ λ² - 2x₁ (mod p)"},
    {"type": "formula", "label": "Ordenada Duplicada", "text": "y₃ ≡ λ · (x₁ - x₃) - y₁ (mod p)"},

    {"type": "h1", "text": "3. Algoritmo de Soporte: Parser de Expresiones y Formato de Potencias"},
    {"type": "body", "text": "Para permitir el ingreso ágil y directo de parámetros de prueba (como los primos de Mersenne 2³¹ - 1 y 2⁶¹ - 1 o números como 2²⁵⁵ - 19), se implementó un analizador sintáctico de descenso recursivo con precedencia de operadores."},
    {"type": "bullet", "bold": "Gramática Libre de Contexto (EBNF):", "text": "El parser evalúa la jerarquía estándar: Expresión (suma/resta) → Término (multiplicación) → Potencia (exponenciación con asociatividad derecha) → Factor (números, signos unarios, paréntesis y formato hexadecimal 0x)."},
    {"type": "formula", "label": "Ejemplos Soportados Directamente", "text": "2^31 - 1   =>   2147483647\n2^61 - 1   =>   2305843009213693951\n2^16 + 1   =>   65537\n2^255 - 19 =>   57896044618658097711785492504343953926634992332820282019728792003956564819949"}
]

# =========================================================================
# SECCIONES EN INGLES
# =========================================================================
sections_en = [
    {"type": "h1", "text": "1. Section 1: Preliminary Functions"},

    {"type": "h2", "text": "Algorithm 1.1: Quadratic Residues and Roots Modulo p > 3"},
    {"type": "body", "text": "Computes the set of all quadratic residues QR_p in the finite field Z_p and extracts the exact pair of square roots associated with each residue."},
    {"type": "bullet", "bold": "Mathematical Basis:", "text": "In any prime finite field Z_p with p > 2, there exist exactly (p - 1) / 2 non-zero quadratic residues and 1 trivial residue (0), yielding a total of ((p - 1) / 2) + 1 quadratic residues."},
    {"type": "bullet", "bold": "O(p) Complexity Reduction:", "text": "Instead of testing every candidate residue r in [0, p-1] against all possible roots (O(p²) complexity), the algorithm directly iterates candidate roots y in [0, (p - 1) / 2] and computes r ≡ y² (mod p)."},
    {"type": "formula", "label": "Residue Generation", "text": "r ≡ y² (mod p)    where y ∈ [0, (p - 1) / 2]"},
    {"type": "bullet", "bold": "Square Roots Determination:", "text": "By modular congruences, if y² ≡ r (mod p), then (-y)² ≡ (p - y)² ≡ r (mod p). Consequently: for y = 0, there is a single root {0}; for each y > 0, there are exactly two distinct symmetric roots {y, p - y}."},
    {"type": "formula", "label": "Square Roots Pair", "text": "Roots(r) = { y,  p - y }    in Z_p  (for all r > 0)"},
    {"type": "bullet", "bold": "O(1) Direct Lookup Hash Table:", "text": "Residues are stored directly indexed by their numerical value in a bucket table. This allows subsequent rational points algorithms to verify the existence of square roots in constant time O(1) without recomputing modular exponentiations."},

    {"type": "h2", "text": "Algorithm 1.2: Rational Points of an Elliptic Curve"},
    {"type": "body", "text": "Determines all coordinate pairs (x, y) satisfying the Weierstraß equation in Z_p, incorporates the point at infinity in 3-dimensional coordinates, and exports results to a CSV file."},
    {"type": "bullet", "bold": "Non-Singularity Verification:", "text": "Before computing points, the algorithm evaluates the discrete discriminant Δ. If Δ ≡ 0 (mod p), the curve has a cusp or node (self-intersection) and lacks an abelian group structure; the algorithm rejects it immediately."},
    {"type": "formula", "label": "Curve Discriminant", "text": "Δ ≡ 4a³ + 27b² (mod p)    [Required condition: Δ ≠ 0 (mod p)]"},
    {"type": "bullet", "bold": "Identity Element Inclusion:", "text": "Following the 3-coordinate specification, the point at infinity 𝒪 is stored as the first group element with fixed coordinates (0, 1, 0), where z = 0."},
    {"type": "formula", "label": "Point at Infinity", "text": "𝒪 = (0, 1, 0)    with z = 0"},
    {"type": "bullet", "bold": "O(p) Affine Points Search:", "text": "For every x in [0, p-1], the cubic polynomial rhs = x³ + ax + b (mod p) is evaluated. Using the quadratic residue table in O(1), if rhs is a quadratic residue, its square roots y are retrieved, forming the affine points (x, y, 1) with z = 1."},
    {"type": "formula", "label": "Elliptic Curve Equation", "text": "y² ≡ x³ + ax + b (mod p)"},
    {"type": "bullet", "bold": "Structured CSV Export:", "text": "The curve parameters (p, a, b, count) and coordinate triples (x, y, z) are exported to a text file with standardized headers."},

    {"type": "h1", "text": "2. Section 2: Elliptic Curve Arithmetic with Big Integers (GMP)"},

    {"type": "h2", "text": "Algorithm 2.1: Non-Singular Elliptic Curve Generation of n Bits"},
    {"type": "body", "text": "Randomly generates a prime number p of arbitrary bit length (from 16 to 2048 bits) and selects coefficients a, b in Z_p ensuring a non-singular curve suitable for cryptography."},
    {"type": "bullet", "bold": "Exact n-Bit Prime Generation:", "text": "Samples an n-bit uniform pseudo-random number using mpz_urandomb. Sets bit n-1 to 1 (ensuring the range [2^(n-1), 2^n - 1]) and bit 0 to 1 (ensuring oddness). Invokes mpz_nextprime (which executes Miller-Rabin probabilistic tests) to locate the next probable prime."},
    {"type": "formula", "label": "n-Bit Prime Range", "text": "p ∈ [ 2^(n-1),  2^n - 1 ]    where p is prime and p > 3"},
    {"type": "bullet", "bold": "Non-Singular Coefficients Selection:", "text": "Samples a, b uniformly in [0, p-1] via mpz_urandomm. Verifies that 4a³ + 27b² ≢ 0 (mod p). Since singular curve density is ~1/p over large fields, the search converges almost instantaneously (< 0.06 s for 2048 bits)."},

    {"type": "h2", "text": "Algorithm 2.2: Point Addition P + Q (where P ≠ ±Q)"},
    {"type": "body", "text": "Computes the geometric-algebraic sum of two points on the elliptic curve using affine coordinates with projective 3-coordinate representation."},
    {"type": "bullet", "bold": "Curve Membership Verification:", "text": "Before performing arithmetic, the algorithm verifies that y² ≡ x³ + ax + b (mod p) for both points. If either point is invalid, the operation aborts with an error code."},
    {"type": "bullet", "bold": "Group Boundary Conditions:", "text": "If P = 𝒪, the result is Q. If Q = 𝒪, the result is P. If x_P = x_Q and y_P ≡ -y_Q (mod p), the secant line is vertical and the sum equals the point at infinity 𝒪 = (0, 1, 0)."},
    {"type": "bullet", "bold": "Secant Slope Calculation (λ):", "text": "The secant line through P and Q has slope λ = (y₂ - y₁) / (x₂ - x₁) (mod p). The modular inverse of the denominator is computed using the extended Euclidean algorithm (mpz_invert)."},
    {"type": "formula", "label": "Secant Slope", "text": "λ ≡ (y₂ - y₁) · (x₂ - x₁)⁻¹ (mod p)"},
    {"type": "bullet", "bold": "Resulting Point Coordinates R = (x₃, y₃, 1):", "text": "Substituting the secant line into the cubic curve equation and applying Vieta's formulas:"},
    {"type": "formula", "label": "Resulting Abscissa", "text": "x₃ ≡ λ² - x₁ - x₂ (mod p)"},
    {"type": "formula", "label": "Resulting Ordinate", "text": "y₃ ≡ λ · (x₁ - x₃) - y₁ (mod p)"},

    {"type": "h2", "text": "Algorithm 2.3: Point Doubling 2P"},
    {"type": "body", "text": "Computes point addition of a point with itself (P + P) by constructing the tangent line to the elliptic curve at point P."},
    {"type": "bullet", "bold": "Implicit Differentiation for Tangent Slope:", "text": "Differentiating 2y(dy/dx) = 3x² + a, the slope of the tangent line at P = (x₁, y₁) is given by:"},
    {"type": "formula", "label": "Tangent Slope", "text": "λ ≡ (3x₁² + a) · (2y₁)⁻¹ (mod p)"},
    {"type": "bullet", "bold": "Vertical Tangent Condition:", "text": "If y₁ ≡ 0 (mod p), the denominator is zero modulo p (no modular inverse exists). Geometrically, the tangent is vertical and converges at infinity: 2P = 𝒪 = (0, 1, 0)."},
    {"type": "bullet", "bold": "Doubled Point Coordinates R = 2P:", "text": "Intersecting the tangent with the cubic equation yields the coordinates:"},
    {"type": "formula", "label": "Doubled Abscissa", "text": "x₃ ≡ λ² - 2x₁ (mod p)"},
    {"type": "formula", "label": "Doubled Ordinate", "text": "y₃ ≡ λ · (x₁ - x₃) - y₁ (mod p)"},

    {"type": "h1", "text": "3. Supporting Algorithm: Power Expression Parser"},
    {"type": "body", "text": "To enable rapid testing without manually calculating large prime expansions (such as Mersenne primes 2³¹ - 1, 2⁶¹ - 1, or 2²⁵⁵ - 19), a recursive-descent parser with operator precedence was implemented."},
    {"type": "bullet", "bold": "Context-Free Grammar (EBNF):", "text": "The parser evaluates the hierarchy: Expression (+, -) → Term (*) → Power (^, right-associative) → Factor (numbers, unary signs, parentheses, and 0x hexadecimal)."},
    {"type": "formula", "label": "Supported Expressions", "text": "2^31 - 1   =>   2147483647\n2^61 - 1   =>   2305843009213693951\n2^16 + 1   =>   65537\n2^255 - 19 =>   57896044618658097711785492504343953926634992332820282019728792003956564819949"}
]

# Generate Spanish DOCX
build_docx("explicacion_algoritmos.docx", "Explicación de Algoritmos — Curvas Elípticas", sections_es, "es")

# Generate English DOCX
build_docx("algorithm_explanations.docx", "Algorithm Explanations — Elliptic Curves", sections_en, "en")
