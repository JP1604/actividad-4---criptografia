
import random
import sympy


def generar_clave(bits=1024):
    # generamos p y q como primos de la mitad del tamaño
    mitad = bits // 2
    p = sympy.randprime(2**(mitad - 1), 2**mitad)
    q = sympy.randprime(2**(mitad - 1), 2**mitad)

    # nos aseguramos que no sean iguales (muy improbable pero por si acaso)
    while q == p:
        q = sympy.randprime(2**(mitad - 1), 2**mitad)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # exponente publico estandar
    d = pow(e, -1, phi)

    # parametros CRT
    dp   = d % (p - 1)
    dq   = d % (q - 1)
    qinv = pow(q, -1, p)  # inverso de q mod p

    sk = {
        "n": n, "e": e, "p": p, "q": q,
        "d": d, "dp": dp, "dq": dq, "qinv": qinv
    }
    return sk


def descifrar_crt(y, sk):
    p, q = sk["p"], sk["q"]
    dp, dq, qinv = sk["dp"], sk["dq"], sk["qinv"]

    # paso 1 y 2: exponenciaciones reducidas
    xp = pow(y, dp, p)
    xq = pow(y, dq, q)

    # paso 3: recombinacion con CRT
    xp_prima = (qinv * (xp - xq)) % p
    x = xq + xp_prima * q

    return x

def invertir_bit(valor, k):
    return valor ^ (1 << k)



def falla_en_xp(y, sk, bit=3):
    p, q = sk["p"], sk["q"]
    dp, dq, qinv = sk["dp"], sk["dq"], sk["qinv"]

    xp = pow(y, dp, p)
    xp = invertir_bit(xp, bit)   # <-- aca introducimos la falla

    xq = pow(y, dq, q)

    xp_prima = (qinv * (xp - xq)) % p
    x_hat = xq + xp_prima * q
    return x_hat



def falla_en_entrada(y, sk, bit=5):
    p, q = sk["p"], sk["q"]
    dp, dq, qinv = sk["dp"], sk["dq"], sk["qinv"]

    y_malo = invertir_bit(y, bit)   # <-- falla en la entrada

    xp = pow(y_malo, dp, p)
    xq = pow(y_malo, dq, q)

    xp_prima = (qinv * (xp - xq)) % p
    x_hat = xq + xp_prima * q
    return x_hat


def falla_en_dp(y, sk, bit=2):
    p, q = sk["p"], sk["q"]
    dq, qinv = sk["dq"], sk["qinv"]

    dp_malo = invertir_bit(sk["dp"], bit)   # <-- dp corrupto

    xp = pow(y, dp_malo, p)   # resultado incorrecto mod p
    xq = pow(y, dq, q)        # este sigue bien

    xp_prima = (qinv * (xp - xq)) % p
    x_hat = xq + xp_prima * q
    return x_hat


def falla_en_qinv(y, sk, bit=7):
    p, q = sk["p"], sk["q"]
    dp, dq = sk["dp"], sk["dq"]

    qinv_malo = invertir_bit(sk["qinv"], bit)   # <-- qinv corrupto

    xp = pow(y, dp, p)
    xq = pow(y, dq, q)

    xp_prima = (qinv_malo * (xp - xq)) % p   # recombinacion incorrecta
    x_hat = xq + xp_prima * q
    return x_hat



def ataque_falla(x_hat, y, sk):
    n, e = sk["n"], sk["e"]

    # calculamos r = x_hat^e - y y luego gcd(r, n)
    r = pow(x_hat, e, n) - y
    g = math.gcd(r, n)

    exito = (g != 1 and g != n)
    return g, exito



def descifrar_seguro(y, sk, funcion_falla=None, bit=None):
    # si le pasamos una funcion de falla la usamos, sino hacemos el descifrado normal
    if funcion_falla is not None and bit is not None:
        x = funcion_falla(y, sk, bit)
    else:
        x = descifrar_crt(y, sk)


    if pow(x, sk["e"], sk["n"]) != y % sk["n"]:
        print(f"  [!] Falla detectada en: {funcion_falla.__name__ if funcion_falla else 'ninguna'}, bit={bit}")
        print(f"  [!] Resultado rechazado, no se devuelve nada.")
        return None

    return x


if __name__ == "__main__":

    print("Generando clave RSA de 1024 bits...")
    sk = generar_clave(1024)
    print(f"  n = {str(sk['n'])[:40]}...")
    print(f"  p = {str(sk['p'])[:30]}...")
    print(f"  q = {str(sk['q'])[:30]}...")
    print()

    y = random.randint(2, sk["n"] - 2)

    x_ok = descifrar_crt(y, sk)
    check = pow(x_ok, sk["e"], sk["n"]) == y % sk["n"]
    print(f"Descifrado CRT correcto: {check}")
    print()

    # fallas a probar
    escenarios = [
        ("T3-a", "Corrupcion de xp",       falla_en_xp,      3),
        ("T3-b", "Corrupcion de entrada y", falla_en_entrada, 5),
        ("T3-c", "Corrupcion de dp",        falla_en_dp,      2),
        ("T3-d", "Corrupcion de qinv",      falla_en_qinv,    7),
    ]

    registros = []

    print("=" * 55)
    for tid, nombre, fn, bit in escenarios:
        print(f"\n{tid} - {nombre} (bit={bit})")

        x_hat = fn(y, sk, bit)
        g, recuperado = ataque_falla(x_hat, y, sk)

        g_str = str(g)
        print(f"  x_hat distinto al correcto: {x_hat != x_ok}")
        print(f"  g = {g_str[:50]}{'...' if len(g_str) > 50 else ''}")
        print(f"  Factor no trivial recuperado: {recuperado}")

        # contramedida
        resultado_seguro = descifrar_seguro(y, sk, fn, bit)
        contramedida_ok = resultado_seguro is None
        print(f"  Contramedida rechazo: {contramedida_ok}")

        registros.append({
            "id": tid,
            "nombre": nombre,
            "bit": bit,
            "x_hat_distinto": x_hat != x_ok,
            "g": g_str,
            "recuperado": recuperado,
            "contramedida_rechazo": contramedida_ok,
        })

    print("\nProbando contramedida sin falla (debe aceptar):")
    res = descifrar_seguro(y, sk)
    print(f"  Resultado: {'aceptado' if res is not None else 'rechazado (error)'}")


    print("\nGuardando results.txt...")
    with open("results.txt", "w", encoding="utf-8") as f:
        f.write("Registro de ejecuciones - RSA-CRT Fault Injection\n")
        f.write("Clave: 1024 bits | e = 65537\n")
        f.write("=" * 55 + "\n\n")
        for r in registros:
            f.write(f"Escenario : {r['id']} - {r['nombre']}\n")
            f.write(f"Bit invertido : {r['bit']}\n")
            f.write(f"x_hat distinto al correcto : {r['x_hat_distinto']}\n")
            f.write(f"g = {r['g'][:80]}{'...' if len(r['g']) > 80 else ''}\n")
            f.write(f"Factor no trivial recuperado : {r['recuperado']}\n")
            f.write(f"Contramedida rechazo : {r['contramedida_rechazo']}\n")
            f.write("\n")
        f.write("=" * 55 + "\n")

    print("Listo, results.txt guardado.")