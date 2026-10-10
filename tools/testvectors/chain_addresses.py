"""独立推导各链地址（测试工具，不进入 App）：只用 Python 标准库，与 Rust 实现没有共享代码。

- BIP39 种子：hashlib.pbkdf2_hmac
- secp256k1 与 BIP32：纯 Python 椭圆曲线运算
- Ed25519 与 SLIP-10：按 RFC 8032 第 6 节参考实现的思路自写
- Keccak-256：纯 Python（与 ur_hdkey_decode.py 相同的写法）
- Base58 / Base58Check、Bech32（BIP173/BIP350 参考算法）

用法：python3 -I tools/testvectors/chain_addresses.py ["助记词"] [passphrase]
不带参数时使用公开测试助记词 abandon×11 about，并核对 SLIP-10 官方向量 1。
注意：不要在联网电脑上输入真实助记词。
"""
import hashlib
import hmac
import sys

# ---------------------------------------------------------------- secp256k1 / BIP32
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def ec_mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, pt)
        pt, k = ec_add(pt, pt), k >> 1
    return r


def ser_p(pt):
    return bytes([2 + pt[1] % 2]) + pt[0].to_bytes(32, "big")


def bip32_path(seed, path):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    for i in path:
        if i >= 2**31:
            data = b"\0" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
        else:
            data = ser_p(ec_mul(k)) + i.to_bytes(4, "big")
        I = hmac.new(c, data, hashlib.sha512).digest()
        k, c = (int.from_bytes(I[:32], "big") + k) % N, I[32:]
    return ec_mul(k)


H = 2**31

# ---------------------------------------------------------------- Ed25519 / SLIP-10
EP = 2**255 - 19
ED = -121665 * pow(121666, EP - 2, EP) % EP


def ed_recover_x(y, sign):
    x2 = (y * y - 1) * pow(ED * y * y + 1, EP - 2, EP)
    x = pow(x2, (EP + 3) // 8, EP)
    if (x * x - x2) % EP != 0:
        x = x * pow(2, (EP - 1) // 4, EP) % EP
    if x % 2 != sign:
        x = EP - x
    return x


EGY = 4 * pow(5, EP - 2, EP) % EP
EGX = ed_recover_x(EGY, 0)
EG = (EGX, EGY, 1, EGX * EGY % EP)


def ed_add(Pt, Q):
    A = (Pt[1] - Pt[0]) * (Q[1] - Q[0]) % EP
    B = (Pt[1] + Pt[0]) * (Q[1] + Q[0]) % EP
    C = 2 * Pt[3] * Q[3] * ED % EP
    D = 2 * Pt[2] * Q[2] % EP
    E, F, Gg, Hh = B - A, D - C, D + C, B + A
    return (E * F % EP, Gg * Hh % EP, F * Gg % EP, E * Hh % EP)


def ed_mul(s, Pt):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = ed_add(Q, Pt)
        Pt, s = ed_add(Pt, Pt), s >> 1
    return Q


def ed_compress(Pt):
    zinv = pow(Pt[2], EP - 2, EP)
    x, y = Pt[0] * zinv % EP, Pt[1] * zinv % EP
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def ed_public(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return ed_compress(ed_mul(a, EG))


def slip10_ed25519(seed, path):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for i in path:
        I = hmac.new(c, b"\0" + k + (i | H).to_bytes(4, "big"), hashlib.sha512).digest()
        k, c = I[:32], I[32:]
    return k, c


# ---------------------------------------------------------------- 编码
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data):
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def b58check(data):
    return b58(data + hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4])


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def bech32_segwit(hrp, prog):
    CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(v):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for x in v:
            b = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ x
            for i in range(5):
                chk ^= gen[i] if (b >> i) & 1 else 0
        return chk

    acc, bits, data = 0, 0, [0]
    for b in prog:
        acc, bits = acc << 8 | b, bits + 8
        while bits >= 5:
            bits -= 5
            data.append(acc >> bits & 31)
    if bits:
        data.append(acc << (5 - bits) & 31)
    hx = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = polymod(hx + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(CH[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


# Keccak-256（与 ur_hdkey_decode.py 相同的独立写法）
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = 2**64 - 1


def keccak256(data):
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % 136)
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), 136):
        for i in range(17):
            A[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        for rc in RC:
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
            A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = ROT[x][y]
                    B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & M64 if r else A[x][y]
            A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            A[0][0] ^= rc
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def eth_checksum(raw20):
    a = raw20.hex()
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(ch.upper() if ch.isalpha() and int(h[i], 16) >= 8 else ch for i, ch in enumerate(a))


def eth_raw(pt):
    return keccak256(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))[12:]


# ---------------------------------------------------------------- 主程序
def main():
    mnemonic = sys.argv[1] if len(sys.argv) > 1 else " ".join(["abandon"] * 11 + ["about"])
    passphrase = sys.argv[2] if len(sys.argv) > 2 else ""
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    if len(sys.argv) == 1:
        s = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        for path in ([], [0], [0, 1, 2, 2, 1000000000]):
            k, c = slip10_ed25519(s, path)
            print(f"SLIP-10 向量1 m/{'/'.join(str(i) + chr(39) for i in path)}: 私钥 {k.hex()} 链码 {c.hex()} 公钥 {ed_public(k).hex()}")
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048)
    for i in (0, 1):
        print(f"BTC  m/84'/0'/0'/0/{i}   {bech32_segwit('bc', hash160(ser_p(bip32_path(seed, [84 + H, H, H, 0, i]))))}")
    for i in (0, 1):
        print(f"tBTC m/84'/1'/0'/0/{i}   {bech32_segwit('tb', hash160(ser_p(bip32_path(seed, [84 + H, 1 + H, H, 0, i]))))}")
    for i in (0, 1):
        print(f"ETH  m/44'/60'/0'/0/{i}  {eth_checksum(eth_raw(bip32_path(seed, [44 + H, 60 + H, H, 0, i])))}")
    for i in (0, 1):
        print(f"DOGE m/44'/3'/0'/0/{i}   {b58check(bytes([0x1E]) + hash160(ser_p(bip32_path(seed, [44 + H, 3 + H, H, 0, i]))))}")
    print(f"tDOGE m/44'/1'/0'/0/0  {b58check(bytes([0x71]) + hash160(ser_p(bip32_path(seed, [44 + H, 1 + H, H, 0, 0]))))}")
    for i in (0, 1):
        print(f"TRON m/44'/195'/0'/0/{i} {b58check(bytes([0x41]) + eth_raw(bip32_path(seed, [44 + H, 195 + H, H, 0, i])))}")
    for i in (0, 1):
        print(f"SOL  m/44'/501'/{i}'/0'  {b58(ed_public(slip10_ed25519(seed, [44, 501, i, 0])[0]))}")
    for i in (0, 1):
        pk = ed_public(slip10_ed25519(seed, [44, 397, i])[0])
        print(f"NEAR m/44'/397'/{i}'     {pk.hex()}  ed25519:{b58(pk)}")


main()
