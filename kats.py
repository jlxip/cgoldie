#!/usr/bin/env python3
import random

# This file generates the random KATs (known-answer tests) that are
# hardcoded into cgoldie.c

# This was originally executed on Python 3.9.6, under macOS 14.5


def bytes2c(b: bytes, n: int) -> str:
    """Encodes bytes as a C array literal"""
    b = [hex(i)[2:].zfill(2) for i in b]
    b = [b[i * n : (i + 1) * n] for i in range(len(b) // n)]
    b = ["0x" + "".join(i[::-1]).zfill(8) for i in b]
    b = ", ".join(b)
    return "{" + b + "}"


def show(var: str):
    """Shows encodings for both CGOLDIE_32 and CGOLDIE_64 modes"""
    print("---", var, "(32 bits) ---")
    print(bytes2c(eval(var), 4))
    print("---", var, "(64 bits) ---")
    print(bytes2c(eval(var), 8))
    print()


if __name__ == "__main__":
    random.seed(0)

    # --- Values ---
    p = 2**448 - 2**224 - 1
    encp = p.to_bytes(56, "little")
    invencp = (2**448 - p).to_bytes(56, "little")
    omega = (2**448 - ((2 * p) % (2**448))).to_bytes(56, "little")
    show("encp")
    show("invencp")
    show("omega")

    # --- Full word multiplication ---
    a = random.randint(0, 2**64 - 1)
    b = random.randint(0, 2**64 - 1)
    cl = (a * b) & ((1 << 64) - 1)
    ch = (a * b) >> 64
    print("--- kat__mul_a 64 ---")
    print(hex(a))
    print("--- kat__mul_b 64 ---")
    print(hex(b))
    print("--- kat__mul_ch 64 ---")
    print(hex(ch))
    print("--- kat__mul_cl 64 ---")
    print(hex(cl))
    print()
    a = a & ((1 << 32) - 1)
    b = b & ((1 << 32) - 1)
    cl = (a * b) & ((1 << 32) - 1)
    ch = (a * b) >> 32
    print("--- kat__mul_a 32 ---")
    print(hex(a))
    print("--- kat__mul_b 32 ---")
    print(hex(b))
    print("--- kat__mul_ch 32 ---")
    print(hex(ch))
    print("--- kat__mul_cl 32 ---")
    print(hex(cl))
    print()

    # --- Partial substraction ---
    kat_psub448_a = random.randbytes(56)
    a = int.from_bytes(kat_psub448_a, "little")
    while True:
        kat_psub448_b = random.randbytes(56)
        b = int.from_bytes(kat_psub448_b, "little")
        if a > b:
            break
    c = a - b
    kat_psub448_c = c.to_bytes(56, "little")
    show("kat_psub448_a")
    show("kat_psub448_b")
    show("kat_psub448_c")

    # --- Multiplication on 2**448 ---
    kat_mul448_1a = random.randbytes(56)
    kat_mul448_1b = random.randbytes(56)
    a = int.from_bytes(kat_mul448_1a, "little")
    b = int.from_bytes(kat_mul448_1b, "little")
    c = a * b
    kat_mul448_1c = c.to_bytes(112, "little")
    show("kat_mul448_1a")
    show("kat_mul448_1b")
    show("kat_mul448_1c")
    kat_mul448_2a = bytes([0xFF for _ in range(56)])
    a = int.from_bytes(kat_mul448_2a, "little")
    c = a * a
    kat_mul448_2c = c.to_bytes(112, "little")
    show("kat_mul448_2a")
    show("kat_mul448_2c")

    # --- Small reduction ---
    a = int.from_bytes(kat_mul448_2a, "little")
    a %= p
    kat_sred_r = a.to_bytes(56, "little")
    show("kat_sred_r")

    # --- Big reduction ---
    a = int.from_bytes(kat_mul448_1c, "little")
    a %= p
    kat_bred_1r = a.to_bytes(56, "little")
    a = int.from_bytes(kat_mul448_2c, "little")
    a %= p
    kat_bred_2r = a.to_bytes(56, "little")
    show("kat_bred_1r")
    show("kat_bred_2r")

    # --- Addition ---
    a = p - 1
    a *= 2
    a %= p
    kat_add_r = a.to_bytes(56, "little")
    show("kat_add_r")

    # --- Substraction ---
    # a < b
    a = random.randint(0, p - 1)
    kat_sub_1a = a.to_bytes(56, "little")
    while True:
        b = random.randint(0, p - 1)
        if a < b:
            break
    kat_sub_1b = b.to_bytes(56, "little")
    c = (a - b) % p
    kat_sub_1c = c.to_bytes(56, "little")
    show("kat_sub_1a")
    show("kat_sub_1b")
    show("kat_sub_1c")
    # a > b
    d = (b - a) % p
    kat_sub_1d = d.to_bytes(56, "little")
    show("kat_sub_1d")

    # --- Multiplication ---
    a = random.randint(0, p - 1)
    b = random.randint(0, p - 1)
    kat_mul_a = a.to_bytes(56, "little")
    kat_mul_b = b.to_bytes(56, "little")
    c = (a * b) % p
    kat_mul_c = c.to_bytes(56, "little")
    show("kat_mul_a")
    show("kat_mul_b")
    show("kat_mul_c")

    # --- Squaring ---
    a = random.randint(0, p - 1)
    kat_square_a = a.to_bytes(56, "little")
    s = (a**2) % p
    kat_square_s = s.to_bytes(56, "little")
    show("kat_square_a")
    show("kat_square_s")

    # --- Iterative squaring ---
    a = random.randint(0, p - 1)
    kat_squaren_a = a.to_bytes(56, "little")
    for _ in range(512):
        a = pow(a, 2, p)
    kat_squaren_b = a.to_bytes(56, "little")
    show("kat_squaren_a")
    show("kat_squaren_b")

    # --- Multiplicative inverse ---
    a = random.randint(2, p - 1)
    kat_inv_a = a.to_bytes(56, "little")
    b = pow(a, -1, p)
    assert b == pow(a, p - 2, p)
    assert (a * b) % p == 1
    kat_inv_b = b.to_bytes(56, "little")
    show("kat_inv_a")
    show("kat_inv_b")

    # --- X448 ---
    def lit2bytes(x):
        assert len(x) % 2 == 0
        x = [x[2 * i : 2 * (i + 1)] for i in range(len(x) // 2)]
        x = "".join(x[::-1])
        x = int(x, 16)
        return x.to_bytes(56, "little")

    # These come from RFC 7748
    kat_x448_1k = lit2bytes(
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
    )
    kat_x448_1u = lit2bytes(
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
    )
    kat_x448_1o = lit2bytes(
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    )
    kat_x448_2k = lit2bytes(
        "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"
    )
    kat_x448_2u = lit2bytes(
        "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"
    )
    kat_x448_2o = lit2bytes(
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    )
    show("kat_x448_1k")
    show("kat_x448_1u")
    show("kat_x448_1o")
    show("kat_x448_2k")
    show("kat_x448_2u")
    show("kat_x448_2o")
