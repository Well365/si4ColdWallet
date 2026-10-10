"""Cargo：C3 依赖来源 / 配置 / 环境 / 构建时代码 / 依赖图隔离，C10 禁用桩。"""
import hashlib
import json
import os
import re
import subprocess
from awlib.common import ROOT, SKIP_TOP, fail


# 会在构建机上执行的代码（build.rs、过程宏）。新增任何一项都必须先审查（P1 安全复核 M9）。
BUILD_TIME_CODE = {
    "third_party/rust-secp256k1/secp256k1-sys/build.rs",
    "third_party/rust-bitcoin/bitcoin/build.rs",
    "third_party/rust-bitcoin/io/build.rs",
}

# .cargo/config.toml 的内容被固定；修改它必须同时修改这里（两处都经过代码审查）
CARGO_CONFIG_SHA256 = "22a2d039364651e26965734b878abf4cf743a4e9b6748e2c1dfbcfc4db5986e7"


# ---------------------------------------------------------------- C3

def cmd_check_cargo(_args):
    ok = True
    cfg = os.path.join(ROOT, ".cargo", "config.toml")
    digest = hashlib.sha256(open(cfg, "rb").read()).hexdigest()
    if digest != CARGO_CONFIG_SHA256:
        print(f"[C3] .cargo/config.toml 被修改：{digest}（期望 {CARGO_CONFIG_SHA256}）")
        ok = False
    # 仓库内只允许根目录的 .cargo/config.toml（Cargo 优先读取无扩展名的 config）
    for dirpath, dirnames, _fns in os.walk(ROOT):
        if dirpath == ROOT:
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP]
        if ".cargo" in dirnames:
            cdir = os.path.join(dirpath, ".cargo")
            entries = sorted(os.listdir(cdir))
            if dirpath != ROOT or entries != ["config.toml"]:
                print(f"[C3] 不允许的 Cargo 配置目录：{os.path.relpath(cdir, ROOT)} {entries}")
                ok = False
    # 上级目录与 CARGO_HOME 中不得有其他 Cargo 配置（它们会被 Cargo 一并加载）
    d = os.path.dirname(ROOT)
    while True:
        for n in ("config", "config.toml"):
            p = os.path.join(d, ".cargo", n)
            if os.path.exists(p):
                print(f"[C3] 上级目录存在 Cargo 配置，会影响构建：{p}")
                ok = False
        if d == os.path.dirname(d):
            break
        d = os.path.dirname(d)
    ch = os.environ.get("CARGO_HOME", "")
    for n in ("config", "config.toml", "credentials", "credentials.toml"):
        if ch and os.path.exists(os.path.join(ch, n)):
            print(f"[C3] CARGO_HOME 中存在配置：{os.path.join(ch, n)}")
            ok = False
    for k in os.environ:
        if (k.startswith("CARGO_") and k not in ("CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_ENCODED_RUSTFLAGS")) \
                or k.startswith(("XCODE_", "GIT_", "SWIFT_", "CLANG_", "RUSTUP_")) \
                or k in ("RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS", "TOOLCHAINS"):
            print(f"[C3] 环境变量可能改变构建：{k}（请先 source tools/env.sh）")
            ok = False
    toml = open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8").read()
    if re.search(r"^\[replace\]", toml, re.M):
        print("[C3] Cargo.toml 中不允许 [replace]")
        ok = False
    meta = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--all-features"],
        cwd=ROOT, capture_output=True, text=True)
    if meta.returncode != 0:
        print(meta.stderr[-2000:])
        fail("[C3] cargo metadata 失败")
    data = json.loads(meta.stdout)
    allowed_roots = (os.path.join(ROOT, "core") + os.sep, os.path.join(ROOT, "third_party") + os.sep)
    resolved = {n["id"] for n in data["resolve"]["nodes"]}
    build_code = set()
    for pkg in data["packages"]:
        if pkg["id"] not in resolved:
            continue
        mp = os.path.realpath(pkg["manifest_path"])
        if pkg.get("source") is not None:
            print(f"[C3] 远程来源：{pkg['name']} {pkg['source']}")
            ok = False
        elif not mp.startswith(allowed_roots):
            print(f"[C3] 包位置不在仓库 core/ 或 third_party/ 下：{pkg['name']} {mp}")
            ok = False
        for t in pkg.get("targets", []):
            src = os.path.realpath(t["src_path"])
            if not src.startswith(allowed_roots):
                print(f"[C3] 目标源码位于仓库之外：{pkg['name']} {src}")
                ok = False
            if set(t.get("kind", [])) & {"custom-build", "proc-macro"}:
                build_code.add(os.path.relpath(src, ROOT))
    # 决策 D1：两个 FFI 库各自单独构建时的依赖图必须隔离（Cargo 会合并同一次构建中各包的 feature）
    for pkg, forbidden in (("aw-ffi-watch", ("aw-keys v", "aw-bip39 v", 'aw-chain-btc feature "signing"',
                                             'aw-chain-evm feature "signing"', 'aw-chain-sol feature "signing"')),
                           ("aw-ffi-signer", ('aw-chain-btc feature "watch"', 'aw-chain-evm feature "watch"',
                                              'aw-chain-sol feature "watch"'))):
        t = subprocess.run(["cargo", "tree", "-p", pkg, "-e", "normal,build,features", "--locked", "--offline",
                            "--prefix", "none", "--target", "aarch64-apple-ios"],
                           cwd=ROOT, capture_output=True, text=True)
        if t.returncode != 0:
            print(f"[C3] cargo tree 失败：{pkg}")
            ok = False
            continue
        hit = sorted({f for f in forbidden for line in t.stdout.splitlines() if line.startswith(f)})
        if hit:
            print(f"[C3] {pkg} 的依赖图中出现不允许的内容（决策 D1）：{hit}")
            ok = False
    if build_code != BUILD_TIME_CODE:
        print(f"[C3] 构建期执行代码集合发生变化（需审查后更新 BUILD_TIME_CODE）：\n"
              f"    新增 {sorted(build_code - BUILD_TIME_CODE)}\n    消失 {sorted(BUILD_TIME_CODE - build_code)}")
        ok = False
    if not ok:
        fail("[C3] 失败")
    print(f"[C3] 通过：{len(resolved)} 个包全部来自仓库内路径（含全部 feature 组合）")


# ---------------------------------------------------------------- C10

STUB_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
STUB_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
STUB_FEATURE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def stub_files(name, version, features, reason):
    """禁用桩的唯一合法内容（决策 D12）。检查 C10 用同一函数重新生成并逐字节比较。"""
    toml = (f"# 禁用桩（决策 D12）：{reason}\n"
            "# 由 tools/vendor/make-stub.sh 生成；启用即编译失败。\n"
            "[package]\n"
            f'name = "{name}"\n'
            f'version = "{version}"\n'
            'edition = "2021"\n'
            'license = "MIT"\n'
            "publish = false\n"
            "\n"
            "[lib]\n"
            'path = "src/lib.rs"\n')
    if features:
        toml += "\n[features]\n" + "".join(f"{f} = []\n" for f in features)
    lib = (f"//! 禁用桩：{name} {version}。{reason}\n"
           f'compile_error!("airgap-wallet：依赖 `{name}` 被禁止启用（决策 D12）。'
           '如确需使用，必须按规则 R1 从上游 git 引入并审查。");\n')
    return toml, lib


def valid_stub_args(name, version, features, reason):
    return (STUB_NAME_RE.match(name) and STUB_VERSION_RE.match(version)
            and all(STUB_FEATURE_RE.match(f) for f in features)
            and reason and not any(c in reason for c in '"\\\n\r{}'))


def cmd_make_stub(args):
    if len(args) != 4:
        fail("用法：make-stub <crate 名> <版本> \"<feature 列表>\" \"<原因>\"")
    name, version, feats, reason = args
    features = feats.split()
    if not valid_stub_args(name, version, features, reason):
        fail("参数不合法")
    d = os.path.join(ROOT, "core", "stubs", name)
    if os.path.lexists(d):
        fail(f"{d} 已存在")
    toml, lib = stub_files(name, version, features, reason)
    os.makedirs(os.path.join(d, "src"))
    open(os.path.join(d, "Cargo.toml"), "w", encoding="utf-8").write(toml)
    open(os.path.join(d, "src", "lib.rs"), "w", encoding="utf-8").write(lib)
    print(f"已生成禁用桩 core/stubs/{name} ({version})")


def cmd_check_stubs(_args):
    base = os.path.join(ROOT, "core", "stubs")
    ok = True
    for name in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        d = os.path.join(base, name)
        files = []
        for dd, _dn, fns in os.walk(d):
            files += [os.path.relpath(os.path.join(dd, f), d) for f in fns]
        if sorted(files) != ["Cargo.toml", os.path.join("src", "lib.rs")]:
            print(f"[C10] 禁用桩 {name} 含多余文件：{files}")
            ok = False
            continue
        toml = open(os.path.join(d, "Cargo.toml"), encoding="utf-8").read()
        lib = open(os.path.join(d, "src", "lib.rs"), encoding="utf-8").read()
        m_reason = re.match(r"# 禁用桩（决策 D12）：(.*)\n", toml)
        m_version = re.search(r'^version = "([^"]*)"$', toml, re.M)
        feats = re.findall(r"^([a-z0-9_-]+) = \[\]$", toml, re.M)
        if not (m_reason and m_version and valid_stub_args(name, m_version.group(1), feats, m_reason.group(1))):
            print(f"[C10] 禁用桩 {name} 的元数据不合法")
            ok = False
            continue
        if (toml, lib) != stub_files(name, m_version.group(1), feats, m_reason.group(1)):
            print(f"[C10] 禁用桩 {name} 与标准模板不一致（只允许 compile_error!）")
            ok = False
    if not ok:
        fail("[C10] 失败")
    print("[C10] 通过：禁用桩与标准模板逐字节一致")
