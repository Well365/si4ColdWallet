"""独立验证"纯骰子模式"生成的助记词（只用 Python 标准库，可在任何离线电脑上运行）。

签名机的纯骰子模式：熵 = SHA-256(骰子点数字符串)，12 词取前 16 字节，24 词取 32 字节，再按 BIP39 转成单词。
用法：python3 -I tools/testvectors/verify_dice.py 12|24
      然后在提示下输入骰子点数（从标准输入读取，不出现在命令行与 shell 历史中）。
也可以手工复算：printf '%s' 点数 | shasum -a 256（不要用 echo -n：macOS 的 sh 会把 "-n" 一起输出）。
注意：在联网电脑上输入真实骰子等于泄露钱包，只用离线电脑。
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[0]).resolve().parents[2]
WORDS = (ROOT / "third_party/python-mnemonic/src/mnemonic/wordlist/english.txt").read_text().split()
if len(WORDS) != 2048:
    raise SystemExit("词表不完整")


def mnemonic(entropy: bytes) -> list:
    bits = len(entropy) * 8
    cs = hashlib.sha256(entropy).digest()
    n = int.from_bytes(entropy, "big") << (bits // 32) | cs[0] >> (8 - bits // 32)
    total = bits + bits // 32
    return [WORDS[(n >> (total - 11 * (i + 1))) & 0x7FF] for i in range(total // 11)]


def quality_problems(dice: str) -> list:
    """与签名机 entropy.rs 的 dice_quality 相同的三项检查"""
    n, problems = len(dice), []
    counts = [dice.count(c) for c in "123456"]
    if sum((6 * c - n) ** 2 for c in counts) * 10 > 359 * 6 * n:
        problems.append("各点数出现次数严重不均（卡方检验）")
    run = best = 1
    for a, b in zip(dice, dice[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    if best >= 10:
        problems.append("有连续 10 个以上相同点数")
    if any(all(dice[i] == dice[i + p] for i in range(n - p)) for p in range(1, min(12, n - 1) + 1)):
        problems.append("点数串有周期性重复")
    return problems


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("12", "24"):
        raise SystemExit("用法：verify_dice.py 12|24（骰子点数从标准输入读取）")
    words = int(sys.argv[1])
    dice = sys.stdin.readline().strip()
    if not dice or set(dice) - set("123456"):
        raise SystemExit("骰子点数只能是 1–6")
    need = 50 if words == 12 else 100
    if len(dice) < need:
        raise SystemExit(f"{words} 词至少需要 {need} 次骰子（签名机会拒绝）")
    for p in quality_problems(dice):
        print(f"警告：{p}——签名机会拒绝这串点数")
    digest = hashlib.sha256(dice.encode()).digest()
    entropy = digest[: 16 if words == 12 else 32]
    print("SHA-256 :", digest.hex())
    print("熵      :", entropy.hex())
    for i, w in enumerate(mnemonic(entropy), 1):
        print(f"{i:2}. {w}")


main()
