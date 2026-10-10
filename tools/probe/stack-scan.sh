#!/usr/bin/env bash
# 秘密残留回归测试：在 iOS 模拟器中运行 stack_scan（见 stack_scan.c 与决策 D16）。
# 秘密模式用 Python 标准库独立计算（PBKDF2-HMAC-SHA512、BIP32 硬化派生），不经过被测代码。
# 用法：stack-scan.sh [模拟器名称，默认 "iPhone 16 Pro"]；需先构建模拟器版 libaw_signer.a
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SIM_NAME="${1:-iPhone 16 Pro}"
OUT="$REPO_ROOT/build/probe"
mkdir -p "$OUT"
# AW_SCAN_LIB 只用于反向对照（换成去掉防护的库，确认扫描能发现残留）
lib="${AW_SCAN_LIB:-$REPO_ROOT/target/aarch64-apple-ios-sim/release/libaw_signer.a}"
[ -f "$lib" ] || { echo "缺少 $lib，先运行 tools/cargo-sb build -p aw-ffi-signer --release --locked --target aarch64-apple-ios-sim"; exit 1; }

pats="$(python3 -I "$REPO_ROOT/tools/probe/stack_patterns.py")"

exe="$OUT/stack-scan-sim"
xcrun --sdk iphonesimulator clang -target arm64-apple-ios17.0-simulator \
  -isysroot "$(xcrun --sdk iphonesimulator --show-sdk-path)" -O1 -Wall -Werror \
  -I "$REPO_ROOT/core/crates/aw-ffi-signer/include" "$REPO_ROOT/tools/probe/stack_scan.c" "$lib" \
  -Wl,-dead_strip -o "$exe"

udid="$(xcrun simctl list devices available | grep -F "$SIM_NAME (" | head -1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/')"
[ -n "$udid" ] || { echo "找不到模拟器 $SIM_NAME"; exit 1; }
state="$(xcrun simctl list devices | grep "$udid" | sed -E 's/.*\((Booted|Shutdown)\).*/\1/')"
[ "$state" = "Booted" ] || xcrun simctl boot "$udid"
# shellcheck disable=SC2086
xcrun simctl spawn "$udid" "$exe" $pats
