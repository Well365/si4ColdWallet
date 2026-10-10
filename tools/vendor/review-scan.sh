#!/usr/bin/env bash
# 为第三方源码生成人工审查清单（规则 R1.4）。
# 只做"把需要人看的地方找出来"，结论必须由人填写。
# 用法：review-scan.sh <名称>
set -euo pipefail

name="${1:?名称}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
src="$REPO_ROOT/third_party/$name"
out_dir="$REPO_ROOT/third_party/REVIEW"
out="$out_dir/$name.md"
[ -d "$src" ] || { echo "不存在：$src" >&2; exit 2; }
mkdir -p "$out_dir"

rel() { sed "s#^$src/##"; }
hits() { # 标题 正则 [文件 glob]
  local title="$1" re="$2" glob="${3:-*.rs}"
  local res
  res="$(grep -rEn --include="$glob" "$re" "$src" 2>/dev/null | rel || true)"
  local n; n="$(grep -rEl --include="$glob" "$re" "$src" 2>/dev/null | wc -l | tr -d ' ' || true)"
  echo "### $title（涉及 $n 个文件，全部列出）"
  echo
  if [ -n "$res" ]; then echo '```'; echo "$res"; echo '```'; else echo "无"; fi
  echo
}

{
  echo "# 审查清单：$name"
  echo
  echo "> 自动生成于 $(date -u +%Y-%m-%d)。以下只列出需要人工判断的位置；**结论一栏必须由审查人填写**。"
  echo
  echo "## 概况"
  echo
  echo "| 项目 | 数量 |"
  echo "|---|---|"
  echo "| 文件总数 | $(find "$src" -type f | wc -l | tr -d ' ') |"
  echo "| Rust 源文件 | $(find "$src" -name '*.rs' | wc -l | tr -d ' ') |"
  echo "| C/C++/汇编文件 | $(find "$src" \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' -o -name '*.S' -o -name '*.s' -o -name '*.asm' \) | wc -l | tr -d ' ') |"
  echo "| Cargo.toml | $(find "$src" -name Cargo.toml | wc -l | tr -d ' ') |"
  echo "| build.rs / 自定义 build 脚本（构建期执行） | $( { find "$src" -name build.rs; grep -rlE '^[[:space:]]*build[[:space:]]*=' --include=Cargo.toml "$src"; } 2>/dev/null | wc -l | tr -d ' ') |"
  echo "| 过程宏 crate（构建期执行） | $(grep -rlE 'proc[-_]macro[[:space:]]*=[[:space:]]*true|crate-type.*proc-macro' --include=Cargo.toml "$src" 2>/dev/null | wc -l | tr -d ' ') |"
  echo "| \`unsafe\` 出现次数 | $(grep -rEo '\bunsafe\b' --include='*.rs' "$src" 2>/dev/null | wc -l | tr -d ' ') |"
  echo
  echo "## 构建期会执行的代码"
  echo
  echo '```'
  find "$src" -name build.rs | rel
  grep -rnE '^[[:space:]]*build[[:space:]]*=' --include=Cargo.toml "$src" 2>/dev/null | rel || true
  grep -rlE 'proc[-_]macro[[:space:]]*=[[:space:]]*true|crate-type.*proc-macro' --include=Cargo.toml "$src" 2>/dev/null | rel || true
  echo '```'
  echo
  echo "## 需要人工看的位置"
  echo
  hits "二进制/外部源码嵌入" 'include_bytes!|include_str!|include!|#\[path'
  hits "网络" 'std::net|TcpStream|UdpSocket|reqwest|hyper|socket|connect\('
  hits "进程与环境" 'std::process|Command::new|env::var|option_env!|env!\('
  hits "文件系统" 'std::fs|File::(open|create)'
  hits "外部函数与动态加载" 'extern "C"|extern \{|#\[link|libc::|dlsym|dlopen|asm!|global_asm!'
  for g in '*.c' '*.h'; do
    hits "C 代码中的系统调用（$g）" '\b(socket|connect|getaddrinfo|fopen|open|system|popen|exec[lv]p?|dlsym|dlopen|syscall)[[:space:]]*\(' "$g"
  done
  echo "## 非文本文件"
  echo
  echo '```'
  find "$src" -type f -print0 | while IFS= read -r -d '' f; do
    if ! python3 -I -c 'import sys; b=open(sys.argv[1],"rb").read(); sys.exit(0 if b"\0" not in b and b.decode("utf-8","strict") is not None else 1)' "$f" 2>/dev/null; then
      echo "${f#"$src"/}"
    fi
  done
  echo '```'
  echo
  echo "## 许可证文件"
  echo
  echo '```'
  find "$src" -maxdepth 2 -iname 'LICENSE*' -o -maxdepth 2 -iname 'COPYING*' | rel
  echo '```'
  echo
  echo "## 审查结论（人工填写）"
  echo
  echo "| 项 | 结论 | 审查人 | 日期 |"
  echo "|---|---|---|---|"
  echo "| build.rs / 过程宏行为是否只做编译所需的事 | | | |"
  echo "| 是否存在网络、进程、文件访问且非必要 | | | |"
  echo "| 二进制文件是否全部为无害测试数据 | | | |"
  echo "| 许可证是否兼容 MIT 项目 | | | |"
  echo "| 是否同意引入 | | | |"
} > "$out"
echo "已生成 $out"
