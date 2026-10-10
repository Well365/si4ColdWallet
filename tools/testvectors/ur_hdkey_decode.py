"""独立的 UR(crypto-hdkey) 解码器（测试工具，不进入 App）。

与 Rust 实现完全独立：bytewords 词表直接从规范文档 bcr-2020-012 解析，CRC32 用 Python 标准库 zlib，
CBOR 自行逐字节解析。用来交叉验证签名机界面上显示的二维码。
用法：python3 -I tools/testvectors/ur_hdkey_decode.py "UR:CRYPTO-HDKEY/..."
"""
import pathlib
import re
import sys
import zlib

ROOT = pathlib.Path(sys.argv[0]).resolve().parents[2]
spec = (ROOT / "third_party/bc-research/papers/bcr-2020-012-bytewords.md").read_text()
words = []
for line in spec.splitlines():
    m = re.match(r"^0x([0-9a-f]{2}): ((?:[a-z]{4} ?){8})$", line.strip())
    if m:
        words += m.group(2).split()
assert len(words) == 256, len(words)
minimal = {w[0] + w[3]: i for i, w in enumerate(words)}

ur = sys.argv[1].strip().lower()
assert ur.startswith("ur:crypto-hdkey/") or ur.startswith("ur:hdkey/"), ur
body = ur.split("/", 1)[1]
assert "/" not in body, "多段 UR，此工具只处理单段"
data = bytes(minimal[body[i:i + 2]] for i in range(0, len(body), 2))
payload, crc = data[:-4], data[-4:]
assert zlib.crc32(payload).to_bytes(4, "big") == crc, "CRC32 不符"


class Cbor:
    def __init__(self, b):
        self.b, self.i = b, 0

    def head(self):
        ib = self.b[self.i]
        self.i += 1
        major, ai = ib >> 5, ib & 31
        if ai < 24:
            return major, ai
        n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        v = int.from_bytes(self.b[self.i:self.i + n], "big")
        self.i += n
        return major, v

    def value(self):
        major, v = self.head()
        if major == 0:
            return v
        if major == 2:
            out = self.b[self.i:self.i + v]
            self.i += v
            return out
        if major == 4:
            return [self.value() for _ in range(v)]
        if major == 5:
            return {self.value(): self.value() for _ in range(v)}
        if major == 6:
            return ("tag", v, self.value())
        if major == 7:
            return {20: False, 21: True, 22: None}[v]
        raise ValueError(major)


hd = Cbor(payload).value()
key = hd[3]
origin = hd[6]
assert origin[0] == "tag" and origin[1] in (304, 40304)
kp = origin[2]
comps = kp[1]
path = "m/" + "/".join(f"{comps[i]}{chr(39) if comps[i + 1] else ''}" for i in range(0, len(comps), 2))
coin_info = hd.get(5, ("tag", 0, {}))[2]
net = coin_info.get(2, 0)
coin = coin_info.get(1, 0)
print(f"类型       crypto-hdkey（{len(payload)} 字节 CBOR，CRC32 正确）")
print(f"币种       {coin}（{'BTC' if coin == 0 else 'ETH / EVM' if coin == 60 else '其他'}）")
print(f"根指纹     {kp[2]:08x}")
print(f"派生路径   {path}")
print(f"网络       {'测试网' if net == 1 else '主网'}")
print(f"账户公钥   {key.hex()}")
print(f"链码       {hd[4].hex()}")

# ---- EVM：独立推导地址 #0、#1（纯 Python 的 secp256k1 与 Keccak-256，与 Rust 实现无共享代码）----
if coin == 60:
    import hashlib
    import hmac

    P = 2**256 - 2**32 - 977
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    def add(a, b):
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

    def mul(k, pt):
        r = None
        while k:
            if k & 1:
                r = add(r, pt)
            pt, k = add(pt, pt), k >> 1
        return r

    def decompress(b):
        x = int.from_bytes(b[1:], "big")
        y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
        return x, y if y % 2 == b[0] % 2 else P - y

    def compress(pt):
        return bytes([2 + pt[1] % 2]) + pt[0].to_bytes(32, "big")

    def ckd_pub(pk, cc, i):
        I = hmac.new(cc, compress(pk) + i.to_bytes(4, "big"), hashlib.sha512).digest()
        return add(mul(int.from_bytes(I[:32], "big"), G), pk), I[32:]

    RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
          0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
          0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
          0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
          0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
          0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    M = 2**64 - 1

    def keccak_f(A):  # A[x][y]，按 FIPS 202 的定义逐步写出
        for rc in RC:
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & M) for x in range(5)]
            A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = ROT[x][y]
                    B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & M if r else A[x][y]
            A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            A[0][0] ^= rc
        return A

    def keccak256(data):
        rate = 136
        msg = bytearray(data) + b"\x01"
        msg += b"\x00" * (-len(msg) % rate)
        msg[-1] |= 0x80
        A = [[0] * 5 for _ in range(5)]
        for off in range(0, len(msg), rate):
            block = msg[off:off + rate]
            for i in range(rate // 8):
                A[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
            A = keccak_f(A)
        return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))

    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def checksum(addr):
        h = keccak256(addr.encode()).hex()
        return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(addr))

    acct, cc = decompress(key), hd[4]
    ext, cc_ext = ckd_pub(acct, cc, 0)
    for i in (0, 1):
        pk, _ = ckd_pub(ext, cc_ext, i)
        raw = pk[0].to_bytes(32, "big") + pk[1].to_bytes(32, "big")
        print(f"地址 #{i}    {checksum(keccak256(raw)[12:].hex())}")
