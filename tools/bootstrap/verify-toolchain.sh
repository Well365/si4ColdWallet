#!/usr/bin/env bash
# 复核工具链未被改动（构建前调用）：
#  - Rust 安装目录指纹 = 仓库中固定的 toolchain/INSTALLED_TREE.sha256（排除含本机路径的安装记录，跨机器一致）
#  - Xcode 由苹果签名、通过 Gatekeeper；AW_FULL_VERIFY=1 时做完整签名校验（约 1 分钟）
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOOLROOT="${AW_TOOLROOT:-$HOME/.airgap-wallet-toolchain/v2}"
expected="$(cat "$REPO_ROOT/toolchain/INSTALLED_TREE.sha256")"
actual="$(python3 -I "$REPO_ROOT/tools/aw.py" toolchain-hash "$TOOLROOT/rust")"
if [ "$expected" != "$actual" ]; then
  echo "[工具链] Rust 安装目录与仓库固定指纹不一致：期望 $expected 实际 $actual"
  exit 1
fi
xcode="$(xcode-select -p | sed 's#/Contents/Developer$##')"
sig="$(codesign -dvv "$xcode" 2>&1)"
grep -q '^Authority=Apple Root CA$' <<<"$sig" && grep -q '^Identifier=com.apple.dt.Xcode$' <<<"$sig" \
  || { echo "[工具链] Xcode 签名链异常：$xcode"; exit 1; }
spctl --assess --type execute "$xcode" 2>/dev/null || { echo "[工具链] Xcode 未通过 Gatekeeper 评估"; exit 1; }
if [ "${AW_FULL_VERIFY:-0}" = 1 ]; then
  codesign --verify --strict "$xcode" || { echo "[工具链] Xcode 完整签名校验失败"; exit 1; }
fi
echo "[工具链] 一致：$("$TOOLROOT/rust/bin/rustc" -V)；Xcode 签名正常（$(xcodebuild -version | head -1)）"
