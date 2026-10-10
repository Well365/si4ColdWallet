#!/usr/bin/env bash
# 检查 C6（单机版）：把仓库复制到两个不同路径，各自从零构建签名机静态库，比对 SHA-256。
# 路径不同而产物相同，说明构建结果不依赖本机路径；真正的 C6 还需要第二台机器独立执行。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASE="${1:-${TMPDIR:-/tmp}/aw-repro}"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
mkdir -p "$BASE"

for side in A_first B_second_longer_path; do
  dst="$BASE/$side/airgap-wallet"
  mkdir -p "$dst"
  rsync -a --delete --exclude /target --exclude /build --exclude /.git "$REPO_ROOT/" "$dst/"
  (
    cd "$dst"
    # shellcheck disable=SC1091
    source tools/env.sh
    python3 -I tools/aw.py check-cargo
    for t in "${TARGETS[@]}"; do
      # 每个库单独构建：同一次 cargo 调用会合并 feature，导致观察机库带入签名代码（决策 D1）
      for pkg in aw-ffi-signer aw-ffi-watch; do
        tools/cargo-sb build -p "$pkg" --release --locked --target "$t" 2>&1 | grep -E '^(error|warning: unused)' || true
      done
      [ -f "target/$t/release/libaw_signer.a" ] && [ -f "target/$t/release/libaw_watch.a" ] || { echo "构建失败：$t"; exit 1; }
    done
  )
done

ok=1
for t in "${TARGETS[@]}"; do
  for lib in libaw_signer.a libaw_watch.a; do
    a="$(shasum -a 256 "$BASE/A_first/airgap-wallet/target/$t/release/$lib" | awk '{print $1}')"
    b="$(shasum -a 256 "$BASE/B_second_longer_path/airgap-wallet/target/$t/release/$lib" | awk '{print $1}')"
    if [ "$a" = "$b" ]; then echo "[C6] 一致 $t/$lib  $a"; else echo "[C6] 不一致 $t/$lib  A=$a  B=$b"; ok=0; fi
  done
done
[ "$ok" -eq 1 ] || { echo "[C6] 失败"; exit 1; }
# 记录结果，供 tools/ios/build-*.sh 比对正式构建的产物
mkdir -p "$REPO_ROOT/build/repro"
for t in "${TARGETS[@]}"; do
  for lib in libaw_signer.a libaw_watch.a; do
    echo "$(shasum -a 256 "$BASE/A_first/airgap-wallet/target/$t/release/$lib" | awk '{print $1}')  $t/$lib"
  done
done > "$REPO_ROOT/build/repro/c6.sha256"
echo "[C6] 通过（单机两路径），结果记录在 build/repro/c6.sha256"
