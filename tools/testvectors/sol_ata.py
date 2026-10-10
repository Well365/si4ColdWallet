"""关联代币账户（ATA）推导的独立实现：只用 Python 标准库，自己做 Ed25519 点解压判断"是否在曲线上"
（RFC 8032 第 5.1.3 节），与 Rust 代码没有共享逻辑。

用法：python3 -I tools/testvectors/sol_ata.py > core/crates/aw-chain-sol/tests/vectors/ata.txt
每行：<钱包 hex> <mint hex> <代币程序 hex> <ATA hex> <bump>
"""
import hashlib
import random

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
ATA_PROGRAM = bytes.fromhex("8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859")
TOKEN = bytes.fromhex("06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9")
TOKEN_2022 = bytes.fromhex("06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc")


def on_curve(b: bytes) -> bool:
    """RFC 8032 点解压：能解出 x 就在曲线上（与 Solana 一样不拒绝 y ≥ p 的非规范编码）。"""
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    y %= P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = (x * pow(2, (P - 1) // 4, P)) % P
    else:
        return False
    if x == 0 and sign == 1:
        return False
    return True


def find_pda(seeds: list[bytes], program: bytes) -> tuple[bytes, int]:
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest()
        if not on_curve(h):
            return h, bump
    raise ValueError("no bump")


def main() -> None:
    rng = random.Random(20261011)
    assert on_curve(bytes([0x58] + [0x66] * 31)), "基点必须在曲线上"
    assert not on_curve(bytes([2] + [0] * 31)), "y = 2 不在曲线上"
    for i in range(60):
        owner = bytes(rng.randrange(256) for _ in range(32))
        mint = bytes(rng.randrange(256) for _ in range(32))
        prog = TOKEN if i % 3 else TOKEN_2022
        ata, bump = find_pda([owner, prog, mint], ATA_PROGRAM)
        print(owner.hex(), mint.hex(), prog.hex(), ata.hex(), bump)


main()
