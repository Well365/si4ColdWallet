"""stack-scan.sh 用的秘密模式：用 Python 标准库独立计算，不经过被测代码。
输出 "名称=十六进制" 列表（测试助记词 abandon×11 about，空密码短语，测试网账户 m/84'/1'/0'、EVM 账户 m/44'/60'/0'）。"""
import hashlib, hmac
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
sentence = ("abandon " * 11 + "about").encode()
seed = hashlib.pbkdf2_hmac("sha512", sentence, b"mnemonic", 2048)
i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
k, c = i[:32], i[32:]
pats = {"master_key": k, "master_chain": c, "seed_lo": seed[:32], "seed_hi": seed[32:]}
ak, ac = k, c
for idx in (84, 1, 0):  # m/84'/1'/0'（测试网），全部硬化，只需 HMAC 与模加法
    i = hmac.new(ac, b"\0" + ak + (idx | 0x80000000).to_bytes(4, "big"), hashlib.sha512).digest()
    ak, ac = ((int.from_bytes(i[:32], "big") + int.from_bytes(ak, "big")) % N).to_bytes(32, "big"), i[32:]
pats["account_key"], pats["account_chain"] = ak, ac
ek, ec = k, c
for idx in (44, 60, 0):  # EVM 账户 m/44'/60'/0'
    i = hmac.new(ec, b"\0" + ek + (idx | 0x80000000).to_bytes(4, "big"), hashlib.sha512).digest()
    ek, ec = ((int.from_bytes(i[:32], "big") + int.from_bytes(ek, "big")) % N).to_bytes(32, "big"), i[32:]
pats["evm_account_key"], pats["evm_account_chain"] = ek, ec
# SLIP-10 Ed25519：主私钥与 Solana 账户 #0 私钥（m/44'/501'/0'/0'）
i = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
pats["ed25519_master_key"] = i[:32]
k, c = i[:32], i[32:]
for idx in (44, 501, 0, 0):
    i = hmac.new(c, b"\0" + k + (idx | 0x80000000).to_bytes(4, "big"), hashlib.sha512).digest()
    k, c = i[:32], i[32:]
pats["sol_account0_key"] = k
# 纯骰子生成路径：骰子串的 SHA-256（即熵）
pats["dice_entropy"] = hashlib.sha256(b"3261633433362244155334522333116113343614426455154252153355654526544131445632166514254645352524633213").digest()
key = sentence.ljust(128, b"\0")
pats["sentence"] = key[:32]
pats["hmac_key_opad"] = bytes(b ^ 0x5C for b in key[:32])
pats["hmac_key_ipad"] = bytes(b ^ 0x36 for b in key[:32])
print(" ".join(f"{n}={v.hex()}" for n, v in pats.items()))
