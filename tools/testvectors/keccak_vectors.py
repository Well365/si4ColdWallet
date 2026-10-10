"""生成 aw-chain-evm 的 SHA3-256 差分测试向量（Python 标准库 hashlib，与我们的实现相互独立）。
用法：python3 -I tools/testvectors/keccak_vectors.py > core/crates/aw-chain-evm/testdata/sha3_256.txt
输入由固定种子的 SHA-256 计数器流生成，结果可复现。"""
import hashlib


def stream(n, label):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]


lengths = list(range(0, 301)) + [399, 400, 401, 543, 544, 545, 1000, 4096]
print("# 输入十六进制（空输入写作 -） SHA3-256 十六进制；由 tools/testvectors/keccak_vectors.py 生成")
for n in lengths:
    data = stream(n, f"aw-sha3/{n}")
    print(f"{data.hex() or '-'} {hashlib.sha3_256(data).hexdigest()}")
