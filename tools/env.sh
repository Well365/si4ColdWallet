# 用法：source tools/env.sh
# 进入项目专用、封闭的构建环境（决策 D10、D14；P1 安全审查 M9）。只影响当前终端。

_aw_repo="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
_aw_toolroot="${AW_TOOLROOT:-$HOME/.airgap-wallet-toolchain/v2}"

case "$_aw_repo" in
  *[[:space:]]*) echo "[env] 仓库路径不能含空格：$_aw_repo"; return 1 2>/dev/null || exit 1 ;;
esac

# 1. 清空一切可能改变 Cargo / rustc / C 编译器 / 链接器行为的环境变量
for _aw_v in $(env | sed -n -E 's/^((CARGO|RUST|CC|CXX|AR|LD|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|TARGET|HOST|DYLD|SDKROOT|DEVELOPER_DIR|LIBRARY_PATH|CPATH|C_INCLUDE_PATH|OBJC_INCLUDE_PATH|MACOSX_DEPLOYMENT_TARGET|IPHONEOS_DEPLOYMENT_TARGET|ZERO_AR_DATE|SOURCE_DATE_EPOCH|XCODE|TOOLCHAINS|GIT_|SWIFT|CLANG|OTHER_|PYTHON)[A-Za-z0-9_]*)=.*/\1/p'); do
  unset "$_aw_v"
done

# 2. 最小 PATH：项目工具链 + 系统目录（Xcode 工具经 /usr/bin/xcrun 调用）
export PATH="$_aw_toolroot/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CARGO_HOME="$_aw_toolroot/cargo-home"
export CARGO_NET_OFFLINE=true

# 3. 可复现：去掉本机绝对路径，固定时间戳（检查 C6）
_aw_sep="$(printf '\037')"
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$_aw_repo=/aw${_aw_sep}--remap-path-prefix=$_aw_toolroot=/toolchain"
export CFLAGS="-ffile-prefix-map=$_aw_repo=/aw"
export SOURCE_DATE_EPOCH=1767225600  # 2026-01-01T00:00:00Z
export ZERO_AR_DATE=1
export IPHONEOS_DEPLOYMENT_TARGET=17.0

export AW_REPO="$_aw_repo"
export AW_TOOLROOT="$_aw_toolroot"
unset _aw_repo _aw_toolroot _aw_sep _aw_v
