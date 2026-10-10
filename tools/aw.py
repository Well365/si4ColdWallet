#!/usr/bin/env python3
"""airgap-wallet 供应链检查工具（P1 安全审查后重写，替代原 bash 版本）。

只用 Python 标准库；必须以 `python3 -I tools/aw.py <命令>` 运行（隔离模式，不加载任何外部模块）。
所有比较都按精确字符串/字节进行，不把文件名当正则。

命令：
  tree-hash <目录>                 计算目录树指纹（NUL 分隔，含文件模式、空目录、符号链接）
  verify-third-party [--release]   C1：third_party 每个条目都登记且指纹一致；--release 时拒绝未审查条目
  scan-binaries                    C2：仓库中除登记的测试数据外不得有非文本文件
  check-cargo                      C3：Cargo 解析出的每个包都来自仓库内路径；配置文件未被篡改
  check-binary <文件或.app>...     C4/C5：导入符号与链接库必须在白名单内
  check-ios-sources                C9：签名机 Swift 源码与 Xcode 工程不得使用禁用 API / 脚本阶段 / 包引用
  verify-upstream [名称...]        重新从上游取 commit，确认本地源码与上游一致（需联网，审查期执行）
  check-stubs                      C10：禁用桩只能包含 compile_error!
  check-asm                        C11：编进程序的源码中不得有内联汇编 / 汇编文件 / 自定义段（登记审查过的除外）
"""
import os
import sys

# 隔离模式（-I）不会把脚本目录加入 sys.path，这里只加入仓库自己的 tools/ 目录；
# 不写 .pyc，避免在仓库里留下二进制文件（C2）
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from awlib.binary import cmd_check_binary  # noqa: E402
from awlib.cargo_checks import cmd_check_cargo, cmd_check_stubs, cmd_make_stub  # noqa: E402
from awlib.common import TOOLCHAIN_META, tree_hash  # noqa: E402
from awlib.repo_scan import cmd_check_asm, cmd_check_ios_sources, cmd_scan_binaries  # noqa: E402
from awlib.thirdparty import cmd_import, cmd_rebaseline, cmd_verify_third_party, cmd_verify_upstream  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd, args = sys.argv[1], sys.argv[2:]
    table = {
        "tree-hash": lambda a: print(tree_hash(a[0])),
        "verify-third-party": cmd_verify_third_party,
        "scan-binaries": cmd_scan_binaries,
        "check-cargo": cmd_check_cargo,
        "check-binary": cmd_check_binary,
        "check-ios-sources": cmd_check_ios_sources,
        "check-stubs": cmd_check_stubs,
        "check-asm": cmd_check_asm,
        "make-stub": cmd_make_stub,
        "toolchain-hash": lambda a: print(tree_hash(a[0], exclude=TOOLCHAIN_META)),
        "verify-upstream": cmd_verify_upstream,
        "rebaseline": cmd_rebaseline,
        "import": cmd_import,
    }
    if cmd not in table:
        print(__doc__)
        sys.exit(2)
    table[cmd](args)



if __name__ == "__main__":
    main()
