"""
Script para graficar los puntos racionales de curvas elipticas a partir de los archivos CSV generados.
Requisito de la Seccion 3, Pregunta 1 del Laboratorio 01.
"""
import sys
import os

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("Para graficar se requiere matplotlib ('pip install matplotlib').")
    sys.exit(1)

def plot_elliptic_curve(csv_path):
    if not os.path.exists(csv_path):
        print(f"Error: Archivo no encontrado: {csv_path}")
        return

    p = None
    a = None
    b = None
    count = None
    xs = []
    ys = []

    with open(csv_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if parts[0] == '' and len(parts) >= 3:
                key, val = parts[1], parts[2]
                if key == 'p': p = val
                elif key == 'a': a = val
                elif key == 'b': b = val
                elif key == 'count': count = val
            elif parts[0] == 'x':
                continue
            elif len(parts) == 3:
                x, y, z = int(parts[0]), int(parts[1]), int(parts[2])
                if z != 0: # Excluir punto al infinito para la grafica en plano afin
                    xs.append(x)
                    ys.append(y)

    plt.figure(figsize=(8, 8))
    plt.scatter(xs, ys, color='royalblue', s=35, alpha=0.8, edgecolors='black', linewidths=0.5, label='Puntos afines')
    plt.title(f"Puntos Racionales de $E(\\mathbb{{F}}_p)$: $y^2 \\equiv x^3 + {a}x + {b} \\pmod{{{p}}}$\nTotal puntos (inc. $\\mathcal{{O}}$): {count}", fontsize=12)
    plt.xlabel("x", fontsize=11)
    plt.ylabel("y", fontsize=11)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()

    out_name = f"grafica_{os.path.splitext(os.path.basename(csv_path))[0]}.png"
    plt.savefig(out_name, dpi=200, bbox_inches='tight')
    print(f"Grafica guardada exitosamente como '{out_name}' ({len(xs)} puntos afines).")
    plt.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        plot_elliptic_curve(sys.argv[1])
    else:
        # Buscar CSVs en el directorio actual
        csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
        if not csv_files:
            print("Uso: python plot_rational_points.py <archivo.csv>")
        else:
            for f in csv_files:
                plot_elliptic_curve(f)
