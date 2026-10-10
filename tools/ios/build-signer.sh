#!/usr/bin/env bash
# 构建签名机（P1 安全复核 H1/H4/M8）：
#  1. 复核工具链 → 构建前全部源码检查
#  2. 清空 target/，沙箱内从零编译 Rust 静态库（禁网、只能写 target/），与 C6 独立构建结果比对
#  3. 清空旧产物；xcodebuild 在清空环境变量的状态下运行；核对实际生效的链接参数
#  4. 构建后再跑一遍全部检查（含产物）
# 用法：tools/ios/build-signer.sh [sim|device]（默认 sim）
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
tools/cargo-sb build -p aw-ffi-signer --release --locked --target "$target"
# 复核四 H1：沙箱里的进程只能写 target/。把库拷到沙箱写不到的 build/lib/，之后的核验和链接都只用这份拷贝
mkdir -p "build/lib/$target"
cp "target/$target/release/libaw_signer.a" "build/lib/$target/libaw_signer.a"
lib="$REPO_ROOT/build/lib/$target/libaw_signer.a"
echo "$(shasum -a 256 "$lib" | awk '{print $1}')  build/lib/$target/libaw_signer.a" | tee "build/libaw_signer-$target.sha256"
# C6：与 tools/repro/build-twice.sh 两路径独立构建的结果比对（代码改动后需重新运行 build-twice.sh）
c6="build/repro/c6.sha256"
got="$(shasum -a 256 "$lib" | awk '{print $1}')"
if [ -f "$c6" ]; then
  want="$(awk -v k="$target/libaw_signer.a" '$2==k {print $1}' "$c6")"
  if [ "$want" = "$got" ]; then echo "[C6] 与两路径独立构建结果一致：$got"
  else echo "[C6] 与独立构建结果不一致：本次 $got，独立构建 ${want:-（无记录）}。代码改过就先重新运行 tools/repro/build-twice.sh"; exit 1; fi
elif [ "${AW_ALLOW_NO_C6:-}" = 1 ]; then
  echo "警告：没有 C6 独立构建结果（build/repro/c6.sha256），因 AW_ALLOW_NO_C6=1 继续；本次产物未经独立复现核对"
else
  echo "缺少 C6 独立构建结果：先运行 tools/repro/build-twice.sh（只做开发调试可设 AW_ALLOW_NO_C6=1 跳过）"; exit 1
fi

rm -rf "$REPO_ROOT/build/xcode" "$REPO_ROOT/build/xcode-obj"
xc=(env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="${TMPDIR:-/tmp}" USER="${USER:-}"
    xcodebuild -project ios/Signer/Signer.xcodeproj -target Signer -configuration Release -sdk "$sdk"
    ARCHS=arm64 SYMROOT="$REPO_ROOT/build/xcode" OBJROOT="$REPO_ROOT/build/xcode-obj" ${sign[@]+"${sign[@]}"})  # bash 3.2 + set -u：空数组不能直接展开

# 实际生效的链接参数必须正好是仓库里写的那一个静态库
ldflags="$("${xc[@]}" -showBuildSettings 2>/dev/null | awk -F' = ' '$1 ~ /^ *OTHER_LDFLAGS$/ {print $2}')"
expected="$REPO_ROOT/ios/Signer/../../build/lib/$target/libaw_signer.a"
[ "$ldflags" = "$expected" ] || { echo "OTHER_LDFLAGS 与预期不符：'$ldflags'"; exit 1; }

log="build/xcodebuild-$kind.log"
if ! "${xc[@]}" build > "$log" 2>&1; then
  grep -E 'error' "$log" | head -20
  echo "xcodebuild 失败（完整日志：$log）"
  exit 1
fi
grep -E 'warning: ' "$log" | grep -v appintentsmetadataprocessor | head -10 || true
# 链接完成后再核对一次：Xcode 实际链接的拷贝没有被改动
[ "$(shasum -a 256 "$lib" | awk '{print $1}')" = "$got" ] || { echo "build/lib 中的静态库在构建过程中被改动"; exit 1; }
app="build/xcode/Release-$sdk/Signer.app"
tools/checks/run-all.sh --artifacts "$app"
echo "完成：$app"
