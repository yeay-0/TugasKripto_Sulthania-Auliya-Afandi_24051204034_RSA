import math

# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    _, x, _ = extended_gcd(e, phi)
    return x % phi

def mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


# ─────────────────────────────────────────────
# STEP 1 - KEY GENERATION
# ─────────────────────────────────────────────

def generate_rsa_keys(p, q):
    print("=" * 55)
    print("  TAHAP 1: KEY GENERATION (PEMBANGKITAN KUNCI)")
    print("=" * 55)

    if not is_prime(p) or not is_prime(q):
        raise ValueError(f"p={p} atau q={q} bukan bilangan prima!")
    if p == q:
        raise ValueError("p dan q tidak boleh sama!")

    print(f"  Pilih dua bilangan prima:")
    print(f"    p = {p}")
    print(f"    q = {q}")

    n = p * q
    print(f"\n  Hitung n = p × q")
    print(f"    n = {p} × {q} = {n}")

    phi = (p - 1) * (q - 1)
    print(f"\n  Hitung φ(n) = (p-1)(q-1)")
    print(f"    φ(n) = ({p}-1)({q}-1) = {phi}")

    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        for candidate in range(3, phi, 2):
            if gcd(candidate, phi) == 1:
                e = candidate
                break
    print(f"\n  Pilih e (public exponent): gcd(e, φ(n)) = 1")
    print(f"    e = {e}  →  gcd({e}, {phi}) = {gcd(e, phi)}")

    d = mod_inverse(e, phi)
    print(f"\n  Hitung d (private exponent): (e × d) mod φ(n) = 1")
    print(f"    d = {d}")
    print(f"    Verifikasi: ({e} × {d}) mod {phi} = {(e * d) % phi}")

    print(f"\n   PUBLIC KEY  : (e={e}, n={n})")
    print(f"   PRIVATE KEY : (d={d}, n={n})")
    print()

    return (e, n), (d, n)


# ─────────────────────────────────────────────
# STEP 2 - ENCRYPTION
# ─────────────────────────────────────────────

def encrypt(plaintext, public_key):
    e, n = public_key

    print("=" * 55)
    print("  TAHAP 2: ENKRIPSI")
    print("=" * 55)
    print(f"  Plaintext  : \"{plaintext}\"")
    print(f"  Public Key : e={e}, n={n}")
    print(f"  Rumus      : C = M^e mod n\n")

    ciphertext = []
    for char in plaintext:
        M = ord(char)
        C = mod_pow(M, e, n)
        ciphertext.append(C)
        print(f"  '{char}' (M={M:4d})  →  C = {M}^{e} mod {n} = {C}")

    print(f"\n   Ciphertext (list of int): {ciphertext}")
    print()
    return ciphertext


# ─────────────────────────────────────────────
# STEP 3 - DECRYPTION
# ─────────────────────────────────────────────

def decrypt(ciphertext, private_key):
    d, n = private_key

    print("=" * 55)
    print("  TAHAP 3: DEKRIPSI")
    print("=" * 55)
    print(f"  Ciphertext  : {ciphertext}")
    print(f"  Private Key : d={d}, n={n}")
    print(f"  Rumus       : M = C^d mod n\n")

    plaintext = ""
    for C in ciphertext:
        M = mod_pow(C, d, n)
        char = chr(M)
        plaintext += char
        print(f"  C={C:6d}  →  M = {C}^{d} mod {n} = {M} = '{char}'")

    print(f"\n   Plaintext hasil dekripsi: \"{plaintext}\"")
    print()
    return plaintext


# ─────────────────────────────────────────────
# INPUT HELPER
# ─────────────────────────────────────────────

def input_prime(label):
    while True:
        try:
            val = int(input(f"  Masukkan {label} (bilangan prima) : "))
            if not is_prime(val):
                print(f"  ⚠  {val} bukan bilangan prima! Coba lagi.\n")
            else:
                return val
        except ValueError:
            print("  ⚠  Input harus berupa angka bulat! Coba lagi.\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("  Masukkan parameter RSA:\n")
    p = input_prime("p")
    q = input_prime("q")

    while p == q:
        print("  ⚠  p dan q tidak boleh sama! Masukkan q yang berbeda.\n")
        q = input_prime("q")

    message = input("  Masukkan pesan (plaintext)        : ")
    while not message:
        print("  ⚠  Pesan tidak boleh kosong!\n")
        message = input("  Masukkan pesan (plaintext)        : ")

    # Validasi n harus lebih besar dari semua nilai ASCII pesan
    n = p * q
    max_ascii = max(ord(c) for c in message)
    if n <= max_ascii:
        print(f"\n  ⚠  n = p×q = {n} terlalu kecil untuk mengenkripsi pesan ini.")
        print(f"     Nilai ASCII terbesar dalam pesan = {max_ascii}.")
        print(f"     Gunakan bilangan prima p dan q yang lebih besar.")
        exit(1)

    print()

    # Step 1: Generate keys
    public_key, private_key = generate_rsa_keys(p, q)

    # Step 2: Encrypt
    cipher = encrypt(message, public_key)

    # Step 3: Decrypt
    result = decrypt(cipher, private_key)

    # Verifikasi
    print("=" * 55)
    print("  VERIFIKASI AKHIR")
    print("=" * 55)
    print(f"  Pesan Asli         : \"{message}\"")
    print(f"  Setelah Enkripsi   : {cipher}")
    print(f"  Setelah Dekripsi   : \"{result}\"")
    match = " BERHASIL!" if message == result else " GAGAL!"
    print(f"  Status             : {match}")
    print()