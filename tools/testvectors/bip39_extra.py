"""独立于 Rust 实现的 BIP39 参考计算，用来补齐官方向量缺少的 15 / 21 词情形（P1 审查 L1）。

只用 Python 标准库（hashlib、unicodedata）；词表读自 third_party/python-mnemonic。
用法：python3 -I tools/testvectors/bip39_extra.py > core/crates/aw-bip39/testdata/extra_vectors.txt
输出每行：熵十六进制|助记词|NFKD 后的 passphrase|种子十六进制
"""
import hashlib
import pathlib
import sys
import unicodedata

ROOT = pathlib.Path(sys.argv[0]).resolve().parents[2]
WORDS = (ROOT / "third_party/python-mnemonic/src/mnemonic/wordlist/english.txt").read_text().split()
assert len(WORDS) == 2048


def mnemonic(entropy: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in entropy)
    cs = hashlib.sha256(entropy).digest()
    bits += "".join(f"{b:08b}" for b in cs)[: len(entropy) * 8 // 32]
    return " ".join(WORDS[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11))


def seed(sentence: str, passphrase: str) -> bytes:
    pw = unicodedata.normalize("NFKD", sentence).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", pw, salt, 2048)


CASES = [
    (bytes(range(20)), ""),
    (bytes([0xFF] * 20), "TREZOR"),
    (bytes(range(28)), ""),
    (bytes([0x80] * 28), "TREZOR"),
    (bytes(range(1, 33)), "Ⅸ 漢字 ü"),  # 非 ASCII passphrase：Rust 侧收到的是 NFKD 之后的字节
]

print("# 生成：tools/testvectors/bip39_extra.py（独立 Python 实现）")
for ent, pp in CASES:
    m = mnemonic(ent)
    nfkd = unicodedata.normalize("NFKD", pp)
    print(f"{ent.hex()}|{m}|{nfkd}|{seed(m, pp).hex()}")
