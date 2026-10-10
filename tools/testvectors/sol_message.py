"""Solana 消息解析的独立实现（只用 Python 标准库，与 Rust 代码没有共享逻辑），用来生成差分测试向量。

用法：python3 -I tools/testvectors/sol_message.py > core/crates/aw-chain-sol/tests/vectors/messages.txt
每行：<十六进制消息> <摘要或 REJECT>
摘要：版本|签名数|只读签名数|只读不签名数|账户数|指令(程序:账户序号列表:数据十六进制;…)|查找表(表首字节:可写数:只读数;…)
随机数用固定种子，输出可复现。
"""
import random
import sys

MAX = 1232


def enc_sv(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def parse(data):
    """返回摘要字符串；任何不合法返回 None。"""
    if not data or len(data) > MAX:
        return None
    pos = 0

    def u8():
        nonlocal pos
        if pos >= len(data):
            raise ValueError
        pos += 1
        return data[pos - 1]

    def take(n):
        nonlocal pos
        if pos + n > len(data):
            raise ValueError
        pos += n
        return data[pos - n:pos]

    def sv():
        val = 0
        for i in range(3):
            b = u8()
            val |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                if i > 0 and b == 0:
                    raise ValueError
                if val > 0xFFFF:
                    raise ValueError
                return val
        raise ValueError

    try:
        version = "legacy"
        if data[0] & 0x80:
            if data[0] & 0x7F:
                return None
            pos = 1
            version = "v0"
        req, ro_s, ro_u = u8(), u8(), u8()
        keys = [take(32) for _ in range(sv())]
        take(32)
        ixs = []
        for _ in range(sv()):
            prog = u8()
            accts = list(take(sv()))
            d = take(sv())
            ixs.append((prog, accts, d))
        lookups = []
        if version == "v0":
            for _ in range(sv()):
                t = take(32)
                w = list(take(sv()))
                r = list(take(sv()))
                lookups.append((t, w, r))
        if pos != len(data):
            return None
    except ValueError:
        return None
    if req == 0 or ro_s >= req or req + ro_u > len(keys):
        return None
    if len(set(keys)) != len(keys):
        return None
    total = len(keys) + sum(len(w) + len(r) for _, w, r in lookups)
    if total > 256:
        return None
    for prog, accts, _ in ixs:
        if prog == 0 or prog >= len(keys):
            return None
        if any(a >= total for a in accts):
            return None
    ix_s = ";".join(f"{p}:{','.join(map(str, a))}:{d.hex()}" for p, a, d in ixs)
    lk_s = ";".join(f"{t[0]:02x}:{len(w)}:{len(r)}" for t, w, r in lookups)
    return f"{version}|{req}|{ro_s}|{ro_u}|{len(keys)}|{ix_s}|{lk_s}"


def random_message(rng):
    v0 = rng.random() < 0.4
    n_keys = rng.randint(2, 12)
    keys = [bytes([rng.randrange(256) for _ in range(32)]) for _ in range(n_keys)]
    req = rng.randint(1, min(3, n_keys - 1))
    ro_s = rng.randint(0, req - 1)
    ro_u = rng.randint(0, n_keys - req)
    m = bytearray()
    if v0:
        m.append(0x80)
    m += bytes([req, ro_s, ro_u]) + enc_sv(n_keys) + b"".join(keys) + bytes(rng.randrange(256) for _ in range(32))
    lookups = []
    if v0:
        for _ in range(rng.randint(0, 2)):
            lookups.append((bytes(rng.randrange(256) for _ in range(32)),
                            [rng.randrange(256) for _ in range(rng.randint(0, 3))],
                            [rng.randrange(256) for _ in range(rng.randint(0, 3))]))
    total = n_keys + sum(len(w) + len(r) for _, w, r in lookups)
    n_ix = rng.randint(0, 4)
    m += enc_sv(n_ix)
    for _ in range(n_ix):
        m.append(rng.randint(1, n_keys - 1))
        accts = [rng.randrange(total) for _ in range(rng.randint(0, 5))]
        m += enc_sv(len(accts)) + bytes(accts)
        d = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 4, 9, 12, 200])))
        m += enc_sv(len(d)) + d
    if v0:
        m += enc_sv(len(lookups))
        for t, w, r in lookups:
            m += t + enc_sv(len(w)) + bytes(w) + enc_sv(len(r)) + bytes(r)
    return bytes(m)


def mutate(rng, m):
    m = bytearray(m)
    kind = rng.randrange(4)
    if kind == 0 and len(m) > 1:
        return bytes(m[: rng.randrange(1, len(m))])
    if kind == 1:
        i = rng.randrange(len(m))
        m[i] = rng.choice([0, 1, 0x7F, 0x80, 0xFF, rng.randrange(256)])
        return bytes(m)
    if kind == 2:
        return bytes(m) + bytes([rng.randrange(256)])
    i = rng.randrange(min(len(m), 8))
    m[i] = rng.randrange(256)
    return bytes(m)


def main():
    rng = random.Random(20261011)
    lines = []
    for _ in range(300):
        m = random_message(rng)
        s = parse(m)
        assert s is not None, m.hex()
        lines.append(f"{m.hex()} {s}")
        bad = mutate(rng, m)
        lines.append(f"{bad.hex()} {parse(bad) or 'REJECT'}")
    sys.stdout.write("\n".join(lines) + "\n")


main()
