#!/usr/bin/env bash
# 构建观察机。与签名机共用供应链检查；观察机可以联网，所以不做签名机的 C4/C9 网络限制，
# 但仍要求：只链接仓库内 Rust 静态库、零第三方包、沙箱编译。
# 用法：tools/ios/build-watcher.sh [sim|device]
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
# shellcheck disable=SC1091
source tools/env.sh
kind="${1:-sim}"
case "$kind" in
  sim)    target=aarch64-apple-ios-sim; sdk=iphonesimulator; sign=(CODE_SIGNING_ALLOWED=NO) ;;
  device) target=aarch64-apple-ios;     sdk=iphoneos;        sign=() ;;
  *) echo "用法：$0 [sim|device]"; exit 2 ;;
esac
# Xcode 会以 777 权限创建 project.xcworkspace 等目录：先收紧，再由 C9 复核（P1 安全审查 LOW）
find ios -type d -perm -0002 -exec chmod o-w {} +
tools/checks/run-all.sh --source-only
# 复核三 H2：每次都从空的 target/ 开始。上一次构建（包括其中运行过的 build.rs）留在 target/ 里的任何东西，
# 都不会进入这次产物；本次构建中运行的构建时代码只有 tools/awlib/cargo_checks.py 中 BUILD_TIME_CODE 固定并审查过的那几份。
tools/cargo-sb clean
tools/cargo-sb build -p aw-ffi-watch --release --locked --target "$target"
# 复核四 H1：沙箱里的进程只能写 target/。把库拷到沙箱写不到的 build/lib/，之后的核验和链接都只用这份拷贝
mkdir -p "build/lib/$target"
cp "target/$target/release/libaw_watch.a" "build/lib/$target/libaw_watch.a"
lib="$REPO_ROOT/build/lib/$target/libaw_watch.a"
# 观察机静态库中不得出现签名机的私钥代码（决策 D1）
# 苹果 nm 读不出 Rust 自带的 compiler_builtins 成员（新版 LLVM 位码）：只放行这一种读取失败，
# 并要求输出中确实有观察机自己的导出符号，证明检查没有空跑
syms="$(nm -g "$lib" 2>build/nm-watch.err)" || true
if grep -v '^$' build/nm-watch.err | grep -qv 'compiler_builtins-'; then
  echo "nm 读取观察机静态库失败："; cat build/nm-watch.err; exit 1
fi
grep -q ' T _aw_evm_from_ur$' <<<"$syms" || { echo "nm 输出中没有观察机的导出符号，检查无效"; exit 1; }
if grep -qE ' T _aw_session_|SigningAccount|to_seed' <<<"$syms"; then
  echo "观察机静态库中出现了签名/种子相关代码"; exit 1
fi
mkdir -p build
# C6：与 tools/repro/build-twice.sh 两路径独立构建的结果比对（代码改动后需重新运行 build-twice.sh）
c6="build/repro/c6.sha256"
got="$(shasum -a 256 "$lib" | awk '{print $1}')"
if [ -f "$c6" ]; then
  want="$(awk -v k="$target/libaw_watch.a" '$2==k {print $1}' "$c6")"
  if [ "$want" = "$got" ]; then echo "[C6] 与两路径独立构建结果一致：$got"
  else echo "[C6] 与独立构建结果不一致：本次 $got，独立构建 ${want:-（无记录）}。代码改过就先重新运行 tools/repro/build-twice.sh"; exit 1; fi
elif [ "${AW_ALLOW_NO_C6:-}" = 1 ]; then
  echo "警告：没有 C6 独立构建结果（build/repro/c6.sha256），因 AW_ALLOW_NO_C6=1 继续；本次产物未经独立复现核对"
else
  echo "缺少 C6 独立构建结果：先运行 tools/repro/build-twice.sh（只做开发调试可设 AW_ALLOW_NO_C6=1 跳过）"; exit 1
fi
rm -rf "$REPO_ROOT/build/xcode-watcher" "$REPO_ROOT/build/xcode-watcher-obj"
xc=(env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="${TMPDIR:-/tmp}" USER="${USER:-}"
    xcodebuild -project ios/Watcher/Watcher.xcodeproj -target Watcher -configuration Release -sdk "$sdk"
    ARCHS=arm64 SYMROOT="$REPO_ROOT/build/xcode-watcher" OBJROOT="$REPO_ROOT/build/xcode-watcher-obj" ${sign[@]+"${sign[@]}"})  # bash 3.2 + set -u：空数组不能直接展开
ldflags="$("${xc[@]}" -showBuildSettings 2>/dev/null | awk -F' = ' '$1 ~ /^ *OTHER_LDFLAGS$/ {print $2}')"
[ "$ldflags" = "$REPO_ROOT/ios/Watcher/../../build/lib/$target/libaw_watch.a" ] || { echo "OTHER_LDFLAGS 与预期不符：'$ldflags'"; exit 1; }
log="build/xcodebuild-watcher-$kind.log"
if ! "${xc[@]}" build > "$log" 2>&1; then
  grep -E 'error' "$log" | head -20; echo "xcodebuild 失败（$log）"; exit 1
fi
[ "$(shasum -a 256 "$lib" | awk '{print $1}')" = "$got" ] || { echo "build/lib 中的静态库在构建过程中被改动"; exit 1; }
echo "完成：build/xcode-watcher/Release-$sdk/Watcher.app"
