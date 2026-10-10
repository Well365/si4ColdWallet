#!/usr/bin/env bash
# 链接探针：对签名机静态库做"真实链接 + 网络符号检查 + 模拟器运行"（检查 C4 的完整形态）。
# 用法：link-probe.sh [模拟器名称，默认 "iPhone 16 Pro"]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SIM_NAME="${1:-iPhone 16 Pro}"
OUT="$REPO_ROOT/build/probe"
mkdir -p "$OUT"
INC="$REPO_ROOT/core/crates/aw-ffi-signer/include"
MIN_IOS="17.0"

link_for() { # rust-target sdk clang-target 输出名
  local rt="$1" sdk="$2" ct="$3" exe="$OUT/$4"
  local lib="$REPO_ROOT/target/$rt/release/libaw_signer.a"
  [ -f "$lib" ] || { echo "缺少 $lib，先运行 cargo build -p aw-ffi-signer --release --target $rt"; exit 1; }
  xcrun --sdk "$sdk" clang -target "$ct" -isysroot "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    -O2 -Wall -Werror -I "$INC" "$REPO_ROOT/tools/probe/link_probe.c" "$lib" \
    -Wl,-dead_strip -o "$exe"
  echo "已链接 $exe"
  python3 -I "$REPO_ROOT/tools/aw.py" check-binary "$exe"
}

link_for aarch64-apple-ios-sim iphonesimulator "arm64-apple-ios${MIN_IOS}-simulator" probe-sim
link_for aarch64-apple-ios     iphoneos        "arm64-apple-ios${MIN_IOS}"           probe-device

echo "== 在模拟器 \"$SIM_NAME\" 中运行"
udid="$(xcrun simctl list devices available | grep -F "$SIM_NAME (" | head -1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/')"
[ -n "$udid" ] || { echo "找不到模拟器 $SIM_NAME"; exit 1; }
state="$(xcrun simctl list devices | grep "$udid" | sed -E 's/.*\((Booted|Shutdown)\).*/\1/')"
[ "$state" = "Booted" ] || xcrun simctl boot "$udid"
xcrun simctl spawn "$udid" "$OUT/probe-sim"
