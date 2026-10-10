#!/usr/bin/env bash
# 从上游 git 引入第三方源码（规则 R1）。实际逻辑在 tools/aw.py import：
#  - 必须给出上游引用（标签或分支），并证明 commit 在其历史中（防 fork 提交）
#  - 关闭 export-ignore/export-subst/eol/ident/filter 等改写，导出与 commit 完全一致的源码
#  - 可选只导出部分路径
# 用法：import.sh <名称> <https 上游> <40 位 commit> <refs/tags/… 或 refs/heads/…> <许可证> [路径…]
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
python3 -I "$REPO_ROOT/tools/aw.py" import "$@"
"$REPO_ROOT/tools/vendor/review-scan.sh" "$1"
