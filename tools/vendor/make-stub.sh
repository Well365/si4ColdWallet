#!/usr/bin/env bash
# 生成"禁用桩"（决策 D12）。逻辑与模板在 tools/aw.py（make-stub / check-stubs 共用同一模板）。
# 用法：make-stub.sh <crate 名> <版本> "<被引用的 feature 列表，空格分隔>" "<为什么不需要>"
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec python3 -I "$REPO_ROOT/tools/aw.py" make-stub "$@"
