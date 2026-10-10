#!/usr/bin/env bash
# 检查 C7：rust-secp256k1 内附的 libsecp256k1 C 源码 = 上游 bitcoin-core/secp256k1 指定 commit
#   + rust-secp256k1 的 5 个公开补丁 + 统一改名。上游 revision 与补丁哈希固定在本脚本中
#   （P1 安全审查 M11：不再从被核对的目录里读取这些输入）。需要联网，审查期执行。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYS="$REPO_ROOT/third_party/rust-secp256k1/secp256k1-sys"
UPSTREAM="https://github.com/bitcoin-core/secp256k1"
REV="1ad5185cd42c0636104129fcc9f6a4bf9c67cc40"
UPSTREAM_REF="refs/heads/master"
CODE="0_10_0"
PATCHES=(
  "secp256k1.h.patch:include/secp256k1.h:9ead56bf95da5de694b711dc4221f852d1d11fae5a4c7edb8367cf951232a873"
  "secp256k1.c.patch:src/secp256k1.c:00bacdbc7414e6d2d34b1e2c8c0d8e4c91b239102e21b3a09fd2bf2cfb489e29"
  "scratch_impl.h.patch:src/scratch_impl.h:0df8a2657dd2e0cdee28a078863812e3989d940a81d3b56857cc2b7328e51315"
  "util.h.patch:src/util.h:cc69445ac7281b30e8d2a3a1f271d5e1285d243aab229c13339afb46cda5feb3"
  "lax_der_parsing.c.patch:contrib/lax_der_parsing.c:79a625013923693908f6c8f698f92433ccc9f2f3831ae6985a58cce47b1ae845"
)

[ "$(sed -n '2p' "$SYS/depend/secp256k1-HEAD-revision.txt")" = "$REV" ] || { echo "[C7] 内附 revision 与固定值不一致"; exit 1; }
for p in "${PATCHES[@]}"; do
  IFS=: read -r file _target hash <<<"$p"
  [ "$(shasum -a 256 "$SYS/depend/$file" | awk '{print $1}')" = "$hash" ] || { echo "[C7] 补丁被改动：$file"; exit 1; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/aw-libsecp.XXXXXX")"
trap 'rm -rf "$work"' EXIT
git -c transfer.fsckObjects=true -C "$work" init -q up
git -c transfer.fsckObjects=true -C "$work/up" fetch -q --filter=blob:none "$UPSTREAM" "+$UPSTREAM_REF:refs/aw/ref"
git -c transfer.fsckObjects=true -C "$work/up" fetch -q "$UPSTREAM" "$REV"
git -C "$work/up" merge-base --is-ancestor "$REV" refs/aw/ref || { echo "[C7] revision 不在上游 $UPSTREAM_REF 历史中"; exit 1; }
mkdir -p "$work/up/.git/info" "$work/gen"
echo '* -export-ignore -export-subst -text -eol -ident -filter -working-tree-encoding' > "$work/up/.git/info/attributes"
git -C "$work/up" archive --format=tar "$REV" | tar -x -C "$work/gen"

D="$work/gen"
for p in "${PATCHES[@]}"; do
  IFS=: read -r file target _hash <<<"$p"
  patch -s "$D/$target" "$SYS/depend/$file"
done
# 保留 patch 生成的 .orig 备份：上游 rust-secp256k1 把 util.h.orig 一并提交了
find "$D" -not -path '*/\.*' -not -name CHANGELOG.md -type f -print0 \
  | xargs -0 sed -i '' "/^#include/!s/secp256k1_/rustsecp256k1_v${CODE}_/g"
find "$D" -not -path '*/\.*' -type f -print0 \
  | xargs -0 sed -i '' "/^#include/!s/ecdsa_signature_parse_der_lax/rustsecp256k1_v${CODE}_ecdsa_signature_parse_der_lax/g"

a="$(python3 -I "$REPO_ROOT/tools/aw.py" tree-hash "$D")"
b="$(python3 -I "$REPO_ROOT/tools/aw.py" tree-hash "$SYS/depend/secp256k1")"
if [ "$a" = "$b" ]; then
  echo "[C7] 通过：内附 C 源码（含文件模式）与\"上游 $REV + 固定补丁\"重新生成的结果一致"
else
  echo "[C7] 失败：重新生成 $a，内附 $b"
  diff -r "$D" "$SYS/depend/secp256k1" | head -40
  exit 1
fi
