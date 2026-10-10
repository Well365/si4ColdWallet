#!/usr/bin/env bash
# 运行全部供应链检查。
# 用法：
#   run-all.sh --artifacts <Signer.app> [<其他 Mach-O>…]   完整检查（含产物 C4/C5）
#   run-all.sh --source-only                              只检查源码与依赖，并明确声明产物未检查
#   追加 --release 时：第三方未完成人工审查即失败
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
# shellcheck disable=SC1091
source tools/env.sh
mode=""; release=""; artifacts=()
while [ $# -gt 0 ]; do
  case "$1" in
    --source-only) mode=source ;;
    --artifacts) mode=full; shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do artifacts+=("$1"); shift; done; continue ;;
    --release) release=--release ;;
    *) echo "未知参数：$1"; exit 2 ;;
  esac
  shift
done
[ -n "$mode" ] || { echo "必须指定 --artifacts <产物…> 或 --source-only"; exit 2; }
[ "$mode" = source ] || [ ${#artifacts[@]} -gt 0 ] || { echo "--artifacts 后面需要至少一个产物"; exit 2; }

rc=0
tools/bootstrap/verify-toolchain.sh          || rc=1
python3 -I tools/aw.py verify-third-party $release || rc=1
python3 -I tools/aw.py scan-binaries         || rc=1
python3 -I tools/aw.py check-cargo           || rc=1
python3 -I tools/aw.py check-stubs           || rc=1
python3 -I tools/aw.py check-asm             || rc=1
python3 -I tools/aw.py check-ios-sources     || rc=1
if [ "$mode" = full ]; then
  python3 -I tools/aw.py check-binary "${artifacts[@]}" || rc=1
fi
if [ -n "$release" ]; then
  # 发布：联网重新与上游核对全部第三方源码与 libsecp256k1；完整校验 Xcode 签名
  python3 -I tools/aw.py verify-upstream     || rc=1
  tools/vendor/verify-libsecp256k1.sh         || rc=1
  AW_FULL_VERIFY=1 tools/bootstrap/verify-toolchain.sh || rc=1
fi
echo
if [ "$rc" -ne 0 ]; then
  echo "== 有检查失败 =="
elif [ "$mode" = source ]; then
  echo "== 源码与依赖检查通过；产物检查（C4/C5）未执行 =="
else
  echo "== 全部检查通过（含产物）=="
fi
[ -n "$release" ] || echo "提示：与上游核对（verify-upstream、C7）只在 --release 时执行（需联网）"
exit "$rc"
