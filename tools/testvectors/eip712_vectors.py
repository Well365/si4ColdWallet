"""EIP-712 差分测试向量（测试工具，不进入 App）：纯 Python 独立实现，与 Rust 没有共享代码。

按 EIP-712 规范逐条实现 encodeType / encodeData / hashStruct；Keccak-256 用纯 Python（FIPS 202 定义）。
用法：python3 -I tools/testvectors/eip712_vectors.py > core/crates/aw-chain-evm/testdata/eip712_vectors.txt
输出格式：每个用例一行 "=== 期望签名哈希"，下一行起是 JSON（单行）。
"""
import json

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


def array_part(t):
    if not t.endswith("]"):
        return None
    i = t.rindex("[")
    return t[:i]


def deps(types, t, found):
    while array_part(t) is not None:
        t = array_part(t)
    if t in found or t not in types:
        return found
    found.append(t)
    for f in types[t]:
        deps(types, f["type"], found)
    return found


def encode_type(types, t):
    d = deps(types, t, [])
    d.remove(t)
    return "".join(f"{x}({','.join(f['type'] + ' ' + f['name'] for f in types[x])})" for x in [t] + sorted(d))


def to_int(v):
    if isinstance(v, int):
        return v
    s = str(v)
    neg = s.startswith("-")
    s = s[1:] if neg else s
    n = int(s, 16) if s.lower().startswith("0x") else int(s)
    return -n if neg else n


def enc(types, t, v):
    a = array_part(t)
    if a is not None:
        return keccak256(b"".join(enc(types, a, x) for x in v))
    if t in types:
        return hash_struct(types, t, v)
    if t == "string":
        return keccak256(v.encode())
    if t == "bytes":
        return keccak256(bytes.fromhex(v[2:]))
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t == "address":
        return bytes(12) + bytes.fromhex(v[2:])
    if t.startswith("bytes"):
        return bytes.fromhex(v[2:]).ljust(32, b"\0")
    if t.startswith("uint"):
        return to_int(v).to_bytes(32, "big")
    if t.startswith("int"):
        return (to_int(v) % 2**256).to_bytes(32, "big")
    raise ValueError(t)


def hash_struct(types, t, v):
    return keccak256(keccak256(encode_type(types, t).encode()) + b"".join(enc(types, f["type"], v[f["name"]]) for f in types[t]))


def digest(td):
    return keccak256(b"\x19\x01" + hash_struct(td["types"], "EIP712Domain", td["domain"])
                     + hash_struct(td["types"], td["primaryType"], td["message"]))


D4 = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
CASES = [
    # 1. EIP-712 规范示例
    {"types": {"EIP712Domain": D4, "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
               "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}]},
     "primaryType": "Mail",
     "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
     "message": {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                 "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"}, "contents": "Hello, Bob!"}},
    # 2. MetaMask signTypedData_v4 示例：结构体数组、地址数组
    {"types": {"EIP712Domain": D4,
               "Group": [{"name": "name", "type": "string"}, {"name": "members", "type": "Person[]"}],
               "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person[]"}, {"name": "contents", "type": "string"}],
               "Person": [{"name": "name", "type": "string"}, {"name": "wallets", "type": "address[]"}]},
     "primaryType": "Mail",
     "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
     "message": {"contents": "Hello, Bob!",
                 "from": {"name": "Cow", "wallets": ["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"]},
                 "to": [{"name": "Bob", "wallets": ["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB", "0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57", "0xB0B0b0b0b0b0B000000000000000000000000000"]}]}},
    # 3. 全部基本类型、负数、嵌套与定长数组、空数组
    {"types": {"EIP712Domain": [{"name": "chainId", "type": "uint256"}],
               "All": [{"name": "a", "type": "uint8"}, {"name": "b", "type": "uint256"}, {"name": "c", "type": "int8"},
                       {"name": "d", "type": "int256"}, {"name": "e", "type": "bool"}, {"name": "f", "type": "bytes"},
                       {"name": "g", "type": "bytes1"}, {"name": "h", "type": "bytes32"}, {"name": "i", "type": "string"},
                       {"name": "j", "type": "address"}, {"name": "k", "type": "uint256[][]"}, {"name": "l", "type": "bytes4[2]"},
                       {"name": "m", "type": "string[]"}]},
     "primaryType": "All", "domain": {"chainId": 11155111},
     "message": {"a": 255, "b": "115792089237316195423570985008687907853269984665640564039457584007913129639935", "c": -128,
                 "d": "-12345678901234567890", "e": True, "f": "0x0102030405", "g": "0xff",
                 "h": "0x" + "ab" * 32, "i": "登录 example.org", "j": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                 "k": [[1, 2], [], ["0x03"]], "l": ["0x01020304", "0xa0b0c0d0"], "m": []}},
    # 4. EIP-2612 Permit
    {"types": {"EIP712Domain": D4,
               "Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"},
                          {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}]},
     "primaryType": "Permit",
     "domain": {"name": "USD Coin", "version": "2", "chainId": 1, "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
     "message": {"owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "spender": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                 "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935", "nonce": 0, "deadline": 1893456000}},
    # 5. Uniswap Permit2 PermitSingle（嵌套结构体、uint160 / uint48）
    {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
               "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
                                 {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}],
               "PermitSingle": [{"name": "details", "type": "PermitDetails"}, {"name": "spender", "type": "address"}, {"name": "sigDeadline", "type": "uint256"}]},
     "primaryType": "PermitSingle",
     "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
     "message": {"details": {"token": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "amount": "1461501637330902918203684832716283019655932542975",
                             "expiration": 1893456000, "nonce": 3},
                 "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "sigDeadline": 1893456000}},
    # 6. 递归类型与 salt
    {"types": {"EIP712Domain": [{"name": "salt", "type": "bytes32"}],
               "Node": [{"name": "value", "type": "uint256"}, {"name": "children", "type": "Node[]"}]},
     "primaryType": "Node", "domain": {"salt": "0x" + "11" * 32},
     "message": {"value": 1, "children": [{"value": 2, "children": []}, {"value": 3, "children": [{"value": 4, "children": []}]}]}},
]

print("# EIP-712 差分测试向量：由 tools/testvectors/eip712_vectors.py（纯 Python 独立实现）生成")
for c in CASES:
    print("===", digest(c).hex())
    print(json.dumps(c, ensure_ascii=False))
