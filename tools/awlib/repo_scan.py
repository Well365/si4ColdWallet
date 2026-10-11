"""仓库文件扫描：C2 非文本文件、C9 iOS 源码禁用 API、C11 汇编与自定义段。"""
import hashlib
import os
import re
import stat
import subprocess
from awlib.common import ALLOWLIST, CHECKS, ROOT, SHA256_RE, SKIP_TOP, TP, fail


EXEC_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
              b"\x7fELF", b"!<arch>\n", b"MZ", b"\x00asm", b"PK\x03\x04", b"\x1f\x8b",
              b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"BZh", b"\xde\xc0\x17\x0b", b"BC\xc0\xde")
ALLOWLIST_DIRS = {"tests", "test", "testdata", "data", "fuzz", "logo", "images"}


def walk_repo():
    """遍历仓库全部文件（不依赖 git 的文件列表）。返回 (相对路径列表, 问题列表)。"""
    files, problems = [], []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = os.path.relpath(dirpath, ROOT)
        if dirpath == ROOT:
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP]
        else:
            if ".git" in dirnames or ".git" in filenames:
                problems.append(f"{rel_dir}/.git（嵌套的 git 仓库，内容会被跳过）")
        for n in dirnames:
            if os.path.islink(os.path.join(dirpath, n)):
                files.append(os.path.normpath(os.path.join(rel_dir, n)))
        for n in filenames:
            files.append(os.path.normpath(os.path.join(rel_dir, n)))
    r = subprocess.run(["git", "-C", ROOT, "ls-files", "-s"], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/")})
    for line in r.stdout.splitlines():
        if line.startswith("160000 "):
            problems.append(f"{line.split(chr(9))[-1]}（git 子模块/gitlink）")
    return sorted(files), problems


def is_text(data):
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def load_allowlist():
    allow = {}
    if not os.path.exists(ALLOWLIST):
        return allow
    with open(ALLOWLIST, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("  ", 2)
            if len(parts) != 3 or not SHA256_RE.match(parts[0]) or not parts[2].startswith("# "):
                fail(f"[C2] BINARY_ALLOWLIST 第 {lineno} 行格式应为 '<sha256>  <路径>  # 原因'")
            if parts[1] in allow:
                fail(f"[C2] BINARY_ALLOWLIST 路径重复：{parts[1]}")
            allow[parts[1]] = parts[0]
    return allow


def cmd_scan_binaries(_args):
    allow = load_allowlist()
    files, bad = walk_repo()
    used = set()
    for rel in files:
        full = os.path.join(ROOT, rel)
        if os.path.basename(rel) == ".DS_Store":
            bad.append(f"{rel}（Finder 生成的二进制文件，请删除）")
            continue
        if os.path.islink(full):
            target = os.readlink(full)
            resolved = os.path.realpath(full)
            if os.path.isabs(target) or not resolved.startswith(ROOT + os.sep):
                bad.append(f"{rel}（符号链接指向仓库之外：{target}）")
            continue
        if not os.path.isfile(full):
            bad.append(f"{rel}（不是普通文件）")
            continue
        with open(full, "rb") as f:
            data = f.read()
        if is_text(data):
            continue
        digest = hashlib.sha256(data).hexdigest()
        if rel in allow:
            parts = rel.split("/")
            # App 图标（决策 D38）：只允许 ios/<App>/<App>/Assets.xcassets/<名>.appiconset/<名>.png，
            # 文件头必须是 PNG；图像由 tools/ios/make_icons.swift 生成，按哈希登记
            app_icon = (len(parts) == 6 and parts[0] == "ios" and parts[3] == "Assets.xcassets"
                        and parts[4].endswith(".appiconset") and parts[5].endswith(".png")
                        and data.startswith(b"\x89PNG\r\n\x1a\n"))
            if not (app_icon or (parts[0] == "third_party" and ALLOWLIST_DIRS & set(parts[2:-1]))):
                bad.append(f"{rel}（登记只允许 third_party 下的测试数据/图片目录，或 App 图标 PNG）")
            elif len(data) >= 64 and data.startswith(EXEC_MAGIC):  # 小于 64 字节不可能是有效的可执行文件/库/压缩包
                bad.append(f"{rel}（登记的文件是可执行/目标/库/压缩格式，不允许登记）")
            elif allow[rel] != digest:
                bad.append(f"{rel}（哈希与登记不符：{digest}）")
            else:
                used.add(rel)
            continue
        bad.append(f"{rel}（非文本文件，sha256={digest}）")
    for rel in sorted(set(allow) - set(files)):
        bad.append(f"{rel}（BINARY_ALLOWLIST 中登记了但不存在）")
    if bad:
        print("\n".join(f"[C2] 禁止：{b}" for b in bad))
        fail("[C2] 失败")
    print(f"[C2] 通过：遍历 {len(files)} 个文件；{len(used)} 个已登记测试数据，其余均为文本")


# ---------------------------------------------------------------- C9

SWIFT_BANNED = (
    "URLSession", "URLRequest", "contentsOf:", "UIApplication.shared.open", "openURL", "UIPasteboard",
    "import Network", "import WebKit", "import MultipeerConnectivity", "import CoreBluetooth",
    "NSClassFromString", "dlopen", "dlsym", "Process(", "NSTask", "os_log", "Logger(", "print(", "NSLog(",
    "UserDefaults", "FileManager", "CloudKit", "NSUbiquitous",
)
PBX_BANNED = ("PBXShellScriptBuildPhase", "shellScript", "XCRemoteSwiftPackageReference",
              "XCLocalSwiftPackageReference", "packageReferences", "packageProductDependencies",
              "XCSwiftPackageProductDependency")


# ios/ 下允许出现的文件类型。Xcode 的同步文件夹会自动编译放进去的任何源码，所以 C/ObjC/C++/汇编一律不允许
IOS_ALLOWED_EXT = {".swift", ".pbxproj", ".modulemap", ".xcworkspacedata", ".plist", ".json", ".png", ".strings"}


def cmd_check_ios_sources(_args):
    ok = True
    for d, dn, fns in os.walk(os.path.join(ROOT, "ios")):
        for n in dn + fns:
            if os.path.islink(os.path.join(d, n)):
                print(f"[C9] ios/ 中不允许符号链接：{os.path.relpath(os.path.join(d, n), ROOT)}")
                ok = False
        for n in fns:
            if n in ("Package.swift", "Package.resolved", "Podfile", "Podfile.lock", "Cartfile", "mirrors.json"):
                print(f"[C9] 禁止的包管理文件：{os.path.relpath(os.path.join(d, n), ROOT)}")
                ok = False
            if os.path.splitext(n)[1] not in IOS_ALLOWED_EXT:
                print(f"[C9] ios/ 中不允许的文件类型：{os.path.relpath(os.path.join(d, n), ROOT)}")
                ok = False
    signer = os.path.join(ROOT, "ios", "Signer")
    shared = os.path.join(ROOT, "ios", "Shared")
    for base in (signer, shared):
        for d, _dn, fns in os.walk(base):
            for n in fns:
                p = os.path.join(d, n)
                rel = os.path.relpath(p, ROOT)
                if n.endswith((".swift", ".m", ".mm", ".c", ".h")):
                    txt = open(p, encoding="utf-8").read()
                    for b in SWIFT_BANNED:
                        # 以字母开头的按标识符边界匹配（避免 fingerprint( 误中 print(）
                        pat = (r"(?<![A-Za-z0-9_])" if b[0].isalnum() else "") + re.escape(b)
                        if re.search(pat, txt):
                            print(f"[C9] 签名机源码使用了禁用 API {b!r}：{rel}")
                            ok = False
                if n == "project.pbxproj" or n.endswith(".xcscheme") or n.endswith(".xcworkspacedata"):
                    txt = open(p, encoding="utf-8").read()
                    for b in PBX_BANNED + ("ExecutionAction", "PreActions", "PostActions"):
                        if b in txt:
                            print(f"[C9] 工程文件含禁止的内容 {b!r}：{rel}")
                            ok = False
                if n in ("Package.swift", "Package.resolved", "Podfile", "Podfile.lock", "Cartfile", "mirrors.json"):
                    print(f"[C9] 禁止的包管理文件：{rel}")
                    ok = False
    for d, dn, fns in os.walk(ROOT):
        if d == ROOT:
            dn[:] = [x for x in dn if x not in SKIP_TOP]
        for n in dn + fns:
            p = os.path.join(d, n)
            if not os.path.islink(p) and os.stat(p).st_mode & stat.S_IWOTH:
                print(f"[C9] 所有人可写：{os.path.relpath(p, ROOT)}")
                ok = False
    if not ok:
        fail("[C9] 失败")
    print("[C9] 通过：签名机源码与工程文件未使用禁用 API、脚本阶段或包引用")


# ---------------------------------------------------------------- C11

# 会被编进 App 的第三方条目（cc-rs、shlex 只在构建时运行；python-mnemonic、bc-ur、bc-research 只提供数据/测试向量）
RUNTIME_ENTRIES = ("rust-bitcoin", "rust-secp256k1", "hex-conservative", "arrayvec", "rust-bech32", "keccak",
                   "ed25519-compact")
# 两个 App 实际编译的包（复核五 M3：与 RUNTIME_ENTRIES 核对，防止新引入的第三方漏扫）
FFI_PACKAGES = ("aw-ffi-signer", "aw-ffi-watch")
ASM_FILE_EXT = (".s", ".S", ".asm", ".sx", ".nasm")
ASM_PATTERNS = {
    ".rs": re.compile(r"\b(?:asm|global_asm|naked_asm)\s*!|\blink_section\b|#\[\s*(?:unsafe\s*\(\s*)?naked\b"),
    ".c": re.compile(r"\b__asm__\b|\b__asm\b|\basm\s*(?:volatile\s*|__volatile__\s*)?\(|\bsection\s*\(|__declspec\s*\(\s*allocate"),
    ".swift": re.compile(r"@_section\b|@_used\b|@_silgen_name\b|@_cdecl\b"),
}
# Xcode 与 cc-rs 会编译的所有 C 系源码（复核四 H3：原先漏了 ObjC / C++）
for _ext in (".h", ".m", ".mm", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".inl", ".ipp", ".metal"):
    ASM_PATTERNS[_ext] = ASM_PATTERNS[".c"]
ASM_ALLOW = os.path.join(CHECKS, "asm.allow")


def asm_scan_roots():
    roots = [os.path.join(TP, n) for n in RUNTIME_ENTRIES]
    return roots + [os.path.join(ROOT, "core"), os.path.join(ROOT, "ios")]


def runtime_third_party():
    """两个 FFI 库（iOS 目标、普通依赖）实际用到的 third_party 条目名"""
    found = set()
    for pkg in FFI_PACKAGES:
        r = subprocess.run(["cargo", "tree", "-p", pkg, "-e", "normal", "--target", "aarch64-apple-ios",
                            "--locked", "--offline", "--prefix", "none", "--format", "{p}"],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"[C11] cargo tree 失败：{pkg}")
        for m in re.finditer(r"\((/[^)]+)\)", r.stdout):
            rel = os.path.relpath(os.path.realpath(m.group(1)), TP)
            if not rel.startswith(".."):
                found.add(rel.split(os.sep, 1)[0])
    return found


def cmd_check_asm(_args):
    """静态二进制检查无法排除"把只读数据当代码间接调用"（见 docs/02 C4 局限），
    所以在源码层面禁止一切能产生/放置机器码的写法：内联汇编、汇编文件、自定义段、裸函数。"""
    missing = sorted(runtime_third_party() - set(RUNTIME_ENTRIES))
    if missing:
        fail(f"[C11] 这些第三方条目会编进 App，但不在扫描列表 RUNTIME_ENTRIES 中：{missing}")
    allow = {}
    with open(ASM_ALLOW, encoding="utf-8") as f:
        for ln in f:
            ln = ln.split("#", 1)[0].strip()
            if ln:
                digest, path = ln.split(None, 1)
                allow[path] = digest
    hits = {}
    for root in asm_scan_roots():
        if not os.path.isdir(root):
            fail(f"[C11] 缺少目录：{root}")
        for d, dns, fns in os.walk(root):
            dns.sort()  # 复核五 M2：不跳过任何子目录（仓库内不允许嵌套 .git，C2 另查）
            for n in sorted(fns):
                full = os.path.join(d, n)
                rel = os.path.relpath(full, ROOT)
                ext = os.path.splitext(n)[1]
                if n.endswith(ASM_FILE_EXT):
                    hits[rel] = "汇编源文件"
                    continue
                pat = ASM_PATTERNS.get(ext)
                if pat is None:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    for no, line in enumerate(fh, 1):
                        if pat.search(line):
                            hits[rel] = f"第 {no} 行：{line.strip()[:80]}"
                            break
    ok = True
    for rel, why in sorted(hits.items()):
        with open(os.path.join(ROOT, rel), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if allow.get(rel) != digest:
            print(f"[C11] 未登记（或登记后被改动）的汇编/自定义段：{rel}（{why}）")
            ok = False
    for rel in sorted(set(allow) - set(hits)):
        print(f"[C11] 登记项已不存在或不再含汇编，请从 asm.allow 删除：{rel}")
        ok = False
    if not ok:
        fail("[C11] 失败")
    print(f"[C11] 通过：{len(hits)} 个含汇编的文件均已登记审查（均不会为 aarch64 编译）")
