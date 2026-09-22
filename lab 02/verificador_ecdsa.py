import tkinter as tk
from tkinter import ttk, messagebox

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('La inversa modular no existe')
    else:
        return x % m

def point_add(P, Q, p, a):
    if P[2] == 0: return Q
    if Q[2] == 0: return P
    x1, y1, z1 = P
    x2, y2, z2 = Q
    
    u1 = (y2 * z1) % p
    u2 = (y1 * z2) % p
    v1 = (x2 * z1) % p
    v2 = (x1 * z2) % p
    
    u = (u1 - u2) % p
    v = (v1 - v2) % p
    
    if v == 0:
        if u == 0:
            return point_double(P, p, a)
        else:
            return (0, 1, 0)
            
    w = (z1 * z2) % p
    v2_sq = (v * v) % p
    v3 = (v2_sq * v) % p
    
    a_val = (u * u * w - v3 - 2 * v2_sq * v2) % p
    
    x3 = (v * a_val) % p
    y3 = (u * (v2_sq * v2 - a_val) - v3 * u2) % p
    z3 = (v3 * w) % p
    
    return (x3, y3, z3)

def point_double(P, p, a):
    x, y, z = P
    if z == 0 or y == 0: return (0, 1, 0)
    
    w = (a * z * z + 3 * x * x) % p
    s = (y * z) % p
    b_val = (x * y * s) % p
    h = (w * w - 8 * b_val) % p
    
    x3 = (2 * h * s) % p
    y3 = (w * (4 * b_val - h) - 8 * y * y * s * s) % p
    z3 = (8 * s * s * s) % p
    
    return (x3, y3, z3)

def point_mul(k, P, p, a):
    R = (0, 1, 0)
    temp = P
    
    if k < 0:
        k = -k
        temp = (temp[0], (-temp[1]) % p, temp[2])
        
    while k > 0:
        if k % 2 == 1:
            R = point_add(R, temp, p, a)
        temp = point_double(temp, p, a)
        k //= 2
        
    return R

def proj_to_affine(P, p):
    x, y, z = P
    if z == 0: return None
    inv_z = mod_inverse(z, p)
    return ((x * inv_z) % p, (y * inv_z) % p)

def verify_ecdsa(p, a, b, n, Gx, Gy, Qx, Qy, hash_m, r, s):
    if not (1 <= r < n and 1 <= s < n):
        return False, "Los valores 'r' o 's' están fuera de rango [1, n-1]"
        
    try:
        w = mod_inverse(s, n)
    except:
        return False, "Fallo al calcular s^-1 mod n. Asegurate de que s sea coprimo con n."
        
    u1 = (hash_m * w) % n
    u2 = (r * w) % n
    
    G = (Gx, Gy, 1)
    Q = (Qx, Qy, 1)
    
    u1G = point_mul(u1, G, p, a)
    u2Q = point_mul(u2, Q, p, a)
    
    R_proj = point_add(u1G, u2Q, p, a)
    R_aff = proj_to_affine(R_proj, p)
    
    if R_aff is None:
        return False, "Firma inválida. El punto resultante es el infinito (O)."
        
    rx = R_aff[0] % n
    if rx == r:
        return True, "¡Firma VÁLIDA! R_x ≡ r (mod n)."
    else:
        return False, f"Firma INVÁLIDA. \nEl valor calculado R_x ({rx}) no coincide con r ({r})."

class ECDSA_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("ECDSA Signature Verifier")
        self.root.geometry("600x850")
        self.root.configure(padx=20, pady=20)
        
        style = ttk.Style()
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        
        ttk.Label(root, text="Verificador de Firmas ECDSA", style='Title.TLabel').pack(pady=(0, 20))
        
        self.entries = {}
        
        # Estructura del formulario
        fields = [
            ("Parámetros de la Curva", [
                ('p', 'Primo (p)'),
                ('a', 'Coeficiente (a)'),
                ('b', 'Coeficiente (b)'),
                ('n', 'Orden del subgrupo (n)')
            ]),
            ("Punto Generador G", [
                ('Gx', 'Coordenada Gx'),
                ('Gy', 'Coordenada Gy')
            ]),
            ("Clave Pública Q", [
                ('Qx', 'Coordenada Qx'),
                ('Qy', 'Coordenada Qy')
            ]),
            ("Mensaje y Firma", [
                ('hash_m', 'Hash del Mensaje (e)'),
                ('r', 'Firma (r)'),
                ('s', 'Firma (s)')
            ])
        ]
        
        # Frame scrollable en caso de pantallas pequeñas
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        for section, items in fields:
            lf = ttk.LabelFrame(main_frame, text=section, padding=10)
            lf.pack(fill=tk.X, pady=5)
            
            for key, label in items:
                row = ttk.Frame(lf)
                row.pack(fill=tk.X, pady=2)
                ttk.Label(row, text=label, width=20).pack(side=tk.LEFT)
                
                # Se utiliza Text en lugar de Entry para permitir números gigantes
                entry = tk.Text(row, height=2, wrap=tk.WORD, font=('Consolas', 9))
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                self.entries[key] = entry
                
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=20)
        
        ttk.Button(btn_frame, text="Verificar Firma", command=self.verify).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cargar Datos de Ejemplo", command=self.load_example).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Limpiar", command=self.clear).pack(side=tk.RIGHT, padx=5)

    def get_val(self, key):
        val = self.entries[key].get("1.0", tk.END).strip()
        if not val:
            raise ValueError(f"El campo '{key}' está vacío.")
        try:
            return int(val)
        except ValueError:
            raise ValueError(f"El campo '{key}' debe ser un número entero.")

    def set_val(self, key, val):
        self.entries[key].delete("1.0", tk.END)
        self.entries[key].insert(tk.END, str(val))

    def verify(self):
        try:
            p = self.get_val('p')
            a = self.get_val('a')
            b = self.get_val('b')
            n = self.get_val('n')
            Gx = self.get_val('Gx')
            Gy = self.get_val('Gy')
            Qx = self.get_val('Qx')
            Qy = self.get_val('Qy')
            hash_m = self.get_val('hash_m')
            r = self.get_val('r')
            s = self.get_val('s')
        except ValueError as e:
            messagebox.showerror("Error de Entrada", str(e))
            return

        valid, msg = verify_ecdsa(p, a, b, n, Gx, Gy, Qx, Qy, hash_m, r, s)
        
        if valid:
            messagebox.showinfo("Resultado: Válido", msg)
        else:
            messagebox.showerror("Resultado: Inválido", msg)

    def clear(self):
        for entry in self.entries.values():
            entry.delete("1.0", tk.END)

    def load_example(self):
        # Ejemplo: secp256k1
        # p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        
        # Private key d = 12345
        # Q = d * G
        Qx = 0xF028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A
        Qy = 0x07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BBD
        
        # Message hash_m = SHA256("test") 
        hash_m = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        
        # k = 98765
        # r = (k * G)_x mod n
        r = 0xFCB2DECF7DBF8A1559F3E83315B25509B8B5FE0BA3C25D7E807D4C3A36D48F06
        # s = k^-1 * (hash_m + d * r) mod n
        s = 0x7BB20608779BC5CBAC2FE4F5FA2464197AD58866BA2CA9C2E1F6DB70BEBEB5E8

        self.set_val('p', p)
        self.set_val('a', a)
        self.set_val('b', b)
        self.set_val('n', n)
        self.set_val('Gx', Gx)
        self.set_val('Gy', Gy)
        self.set_val('Qx', Qx)
        self.set_val('Qy', Qy)
        self.set_val('hash_m', hash_m)
        self.set_val('r', r)
        self.set_val('s', s)

if __name__ == "__main__":
    root = tk.Tk()
    app = ECDSA_UI(root)
    root.mainloop()
