#!/usr/bin/env bash
# 安装并验证项目专用 Rust 工具链（规则 R4、决策 D10、D14）。
#
# 不使用 rustup。直接下载 Rust 官方"独立安装包"，每个包都有单独的 GPG 签名：
#   1. 导入 Rust 发布公钥，核对写死的指纹
#   2. 渠道清单与每个安装包：严格验签（必须 GOODSIG + VALIDSIG 指纹，且无 BAD/EXP/REV/ERR）
#   3. 安装包哈希 = 已验签清单中的 xz_hash = 仓库中固定的 toolchain/PINNED.sha256
#   4. 以上全部通过后，才解压并运行包内的 install.sh（干净环境）
#   5. 记录安装后目录指纹，供 tools/bootstrap/verify-toolchain.sh 每次构建前复核
#
# 第一次运行且没有 PINNED.sha256 时，会生成它并提示：必须在第二个网络/第二台机器独立运行比对后再提交。
set -euo pipefail

RUST_VERSION="1.99.0"
DIST_DATE="2026-10-01"
HOST="aarch64-apple-darwin"
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
COMPONENTS="rustc,cargo,rust-std-aarch64-apple-darwin,clippy-preview,rustfmt-preview"
# Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>
# 2026-10-10 交叉核对：static.rust-lang.org/rust-key.gpg.ascii 与 keybase.io/rust 一致
RUST_KEY_FPR="108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
DIST="https://static.rust-lang.org/dist/$DIST_DATE"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PINNED="$REPO_ROOT/toolchain/PINNED.sha256"
TOOLROOT="${AW_TOOLROOT:-$HOME/.airgap-wallet-toolchain/v2}"
PREFIX="$TOOLROOT/rust"
GNUPGHOME="$TOOLROOT/gnupg"
DL="$TOOLROOT/downloads"

log() { printf '\033[1m[toolchain]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[toolchain] 失败：%s\033[0m\n' "$*" >&2; exit 1; }
fetch() { curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2" || die "下载失败 $1"; }
sha() { shasum -a 256 "$1" | awk '{print $1}'; }

strict_verify() { # 签名文件 数据文件
  local status
  status="$(GNUPGHOME="$GNUPGHOME" gpg --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null || true)"
  grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" || die "签名无效：$(basename "$2")"
  grep -q "^\[GNUPG:\] VALIDSIG $RUST_KEY_FPR " <<<"$status" || die "签名不是由固定指纹的公钥做出：$(basename "$2")"
  if grep -Eq '^\[GNUPG:\] (BADSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|ERRSIG|NO_PUBKEY)' <<<"$status"; then
    die "签名状态异常（过期/吊销/错误）：$(basename "$2")"
  fi
}

manifest_xz_hash() { # 包名 目标
  awk -v sec="[pkg.$1.target.$2]" '$0 == sec {f=1; next} /^\[/{f=0} f && /^xz_hash = /{gsub(/"/, "", $3); print $3}' "$MANIFEST"
}

check_pinned() { # 文件名 哈希
  if [ -f "$PINNED" ]; then
    local expected
    expected="$(awk -v n="$1" '$2 == n {print $1}' "$PINNED")"
    [ -n "$expected" ] || die "PINNED.sha256 中没有 $1"
    [ "$expected" = "$2" ] || die "$1 哈希与仓库固定值不一致：$2 vs $expected"
  else
    printf '%s  %s\n' "$2" "$1" >> "$PINNED.new"
  fi
}

[ ! -e "$PREFIX" ] || die "$PREFIX 已存在；重新安装请先把它移走"
mkdir -p "$DL" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
rm -f "$PINNED.new"

log "1/5 导入 Rust 发布公钥并核对指纹"
fetch "https://static.rust-lang.org/rust-key.gpg.ascii" "$DL/rust-key.gpg.ascii"
GNUPGHOME="$GNUPGHOME" gpg --batch --quiet --import "$DL/rust-key.gpg.ascii" 2>/dev/null || true
GNUPGHOME="$GNUPGHOME" gpg --batch --with-colons --fingerprint "$RUST_KEY_FPR" 2>/dev/null \
  | grep -q "^fpr:::::::::$RUST_KEY_FPR:" || die "公钥指纹不匹配"

log "2/5 渠道清单：严格验签"
MANIFEST="$DL/channel-rust-$RUST_VERSION.toml"
fetch "https://static.rust-lang.org/dist/channel-rust-$RUST_VERSION.toml" "$MANIFEST"
fetch "https://static.rust-lang.org/dist/channel-rust-$RUST_VERSION.toml.asc" "$MANIFEST.asc"
strict_verify "$MANIFEST.asc" "$MANIFEST"
grep -q "^date = \"$DIST_DATE\"$" "$MANIFEST" || die "清单日期不是 $DIST_DATE"
check_pinned "channel-rust-$RUST_VERSION.toml" "$(sha "$MANIFEST")"

log "3/5 安装包：严格验签 + 与清单、固定值三方核对"
PKGS=("rust:$HOST")
for t in "${IOS_TARGETS[@]}"; do PKGS+=("rust-std:$t"); done
for p in "${PKGS[@]}"; do
  pkg="${p%%:*}"; target="${p##*:}"
  file="$pkg-$RUST_VERSION-$target.tar.xz"
  fetch "$DIST/$file" "$DL/$file"
  fetch "$DIST/$file.asc" "$DL/$file.asc"
  strict_verify "$DL/$file.asc" "$DL/$file"
  h="$(sha "$DL/$file")"
  [ "$h" = "$(manifest_xz_hash "$pkg" "$target")" ] || die "$file 哈希与已验签清单不一致"
  check_pinned "$file" "$h"
  log "    通过：$file"
done

log "4/5 解压并安装到 $PREFIX（干净环境）"
for p in "${PKGS[@]}"; do
  pkg="${p%%:*}"; target="${p##*:}"
  file="$pkg-$RUST_VERSION-$target.tar.xz"
  work="$(mktemp -d "${TMPDIR:-/tmp}/aw-rust.XXXXXX")"
  tar -xJf "$DL/$file" -C "$work"
  dir="$work/$pkg-$RUST_VERSION-$target"
  if [ "$pkg" = "rust" ]; then
    env -i PATH=/usr/bin:/bin HOME="$HOME" bash "$dir/install.sh" --prefix="$PREFIX" \
      --disable-ldconfig --components="$COMPONENTS" >/dev/null
  else
    env -i PATH=/usr/bin:/bin HOME="$HOME" bash "$dir/install.sh" --prefix="$PREFIX" \
      --disable-ldconfig >/dev/null
  fi
  rm -rf "$work"
done
mkdir -p "$TOOLROOT/cargo-home"

log "5/5 记录"
INSTALLED_TREE="$(python3 -I "$REPO_ROOT/tools/aw.py" toolchain-hash "$PREFIX")"
if [ -f "$REPO_ROOT/toolchain/INSTALLED_TREE.sha256" ]; then
  [ "$(cat "$REPO_ROOT/toolchain/INSTALLED_TREE.sha256")" = "$INSTALLED_TREE" ] \
    || die "安装结果与仓库固定指纹不一致：$INSTALLED_TREE"
else
  echo "$INSTALLED_TREE" > "$REPO_ROOT/toolchain/INSTALLED_TREE.sha256"
fi
RUSTC_V="$("$PREFIX/bin/rustc" -V)"
{
  echo "# 由 tools/bootstrap/install-toolchain.sh 生成（本机信息，供复核）。"
  echo "rust_version = \"$RUST_VERSION\""
  echo "rustc = \"$RUSTC_V\""
  echo "dist_date = \"$DIST_DATE\""
  echo "rust_signing_key_fpr = \"$RUST_KEY_FPR\""
  echo "components = \"$COMPONENTS\""
  echo "ios_targets = \"${IOS_TARGETS[*]}\""
  echo "xcode = \"$(xcodebuild -version | tr '\n' ' ' | sed 's/ $//')\""
  echo "apple_clang = \"$(clang --version | head -1)\""
} > "$REPO_ROOT/toolchain/TOOLCHAIN.lock"

if [ -f "$PINNED.new" ]; then
  mv "$PINNED.new" "$PINNED"
  printf '\033[33m[toolchain] 首次运行：已生成 toolchain/PINNED.sha256。\n'
  printf '            提交前必须在另一个网络或另一台机器上独立运行本脚本，确认得到相同的哈希。\033[0m\n'
fi
log "完成：$RUSTC_V。之后用 source tools/env.sh 进入环境"
