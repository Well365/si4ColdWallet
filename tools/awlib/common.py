"""公共部分：仓库路径常量、失败退出、目录树指纹、MANIFEST 读写、白名单读取、git 调用。"""
import fnmatch
import hashlib
import os
import re
import stat
import subprocess
import sys


ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
TP = os.path.join(ROOT, "third_party")
MANIFEST = os.path.join(TP, "MANIFEST.toml")
ALLOWLIST = os.path.join(TP, "BINARY_ALLOWLIST")
CHECKS = os.path.join(ROOT, "tools", "checks")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_KEYS = ("name", "upstream", "ref", "commit", "license", "paths", "tree_sha256", "imported_at", "review")
# 工具链安装目录中含本机路径的安装记录，不参与指纹（使指纹在不同机器上一致）
TOOLCHAIN_META = ("lib/rustlib/install.log", "lib/rustlib/manifest-*", "lib/rustlib/uninstall.sh")


def fail(msg):
    print(msg)
    sys.exit(1)


# ---------------------------------------------------------------- 目录指纹

def tree_hash(root, exclude=()):
    """目录树指纹。记录：相对路径、类型、可执行位、内容 SHA-256、符号链接目标、空目录。
    各字段以 NUL 分隔、记录以 NUL+换行结束，文件名中的任何字符都无法伪造记录边界。
    指向目录树外部或使用绝对路径的符号链接直接报错。"""
    root = os.path.realpath(root)
    if not os.path.isdir(root):
        raise SystemExit(f"不是目录：{root}")
    records = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".git" or rel_dir.startswith(".git" + os.sep):
            continue
        if ".git" in dirnames and dirpath == root:
            dirnames.remove(".git")
        entries = sorted(dirnames + filenames)
        if not entries and rel_dir != ".":
            records.append(("D", rel_dir, "", ""))
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            full = os.path.join(dirpath, name)
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if any(fnmatch.fnmatchcase(rel, pat) for pat in exclude):
                continue
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(full)
                resolved = os.path.realpath(full)
                if os.path.isabs(target) or not (resolved == root or resolved.startswith(root + os.sep)):
                    raise SystemExit(f"符号链接指向目录树之外：{rel} -> {target}")
                records.append(("L", rel, "", target))
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                mode = "x" if st.st_mode & stat.S_IXUSR else "-"
                records.append(("F" + mode, rel, h.hexdigest(), ""))
            else:
                raise SystemExit(f"不支持的文件类型：{rel}")
    records.sort(key=lambda r: r[1].encode("utf-8", "surrogateescape"))
    h = hashlib.sha256()
    for kind, rel, digest, target in records:
        for field in (kind, rel, digest, target):
            h.update(field.encode("utf-8", "surrogateescape"))
            h.update(b"\0")
        h.update(b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------- MANIFEST

def parse_manifest():
    if not os.path.exists(MANIFEST):
        return []
    entries, cur = [], None
    with open(MANIFEST, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line == "[[source]]":
                cur = {}
                entries.append(cur)
                continue
            m = re.fullmatch(r'([a-z_0-9]+) = "([^"\\]*)"', line)
            if not m or cur is None:
                fail(f"[MANIFEST] 第 {lineno} 行格式不合法：{line!r}")
            key, val = m.group(1), m.group(2)
            if key not in MANIFEST_KEYS:
                fail(f"[MANIFEST] 第 {lineno} 行未知字段：{key}")
            if key in cur:
                fail(f"[MANIFEST] 第 {lineno} 行字段重复：{key}")
            cur[key] = val
    names = set()
    for e in entries:
        for k in ("name", "upstream", "ref", "commit", "license", "tree_sha256", "review"):
            if k not in e:
                fail(f"[MANIFEST] 条目缺少字段 {k}：{e}")
        if not NAME_RE.match(e["name"]) or e["name"] in names:
            fail(f"[MANIFEST] 名称不合法或重复：{e['name']!r}")
        names.add(e["name"])
        if not SHA1_RE.match(e["commit"]) or not SHA256_RE.match(e["tree_sha256"]):
            fail(f"[MANIFEST] commit 或指纹格式不对：{e['name']}")
        if not e["upstream"].startswith("https://"):
            fail(f"[MANIFEST] 只接受 https 上游：{e['name']}")
    return entries


def write_manifest(entries):
    lines = ["# 第三方源码登记（规则 R1）。由 tools/vendor/import.sh 维护；人工修改 review 字段。", ""]
    for e in entries:
        lines.append("[[source]]")
        for k in MANIFEST_KEYS:
            if k in e:
                lines.append(f'{k} = "{e[k]}"')
        lines.append("")
    tmp = MANIFEST + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp, MANIFEST)


# ---------------------------------------------------------------- C2

SKIP_TOP = (".git", "target", "build")  # 版本库元数据与构建产物（构建产物由 C4/C5 检查）


def read_list(name):
    p = os.path.join(CHECKS, name)
    with open(p, encoding="utf-8") as f:
        return {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}


# ---------------------------------------------------------------- 上游核对 / 导出

def git(*args, cwd=None, check=True):
    return subprocess.run(["git", "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", *args],
                          cwd=cwd, check=check, capture_output=True)
