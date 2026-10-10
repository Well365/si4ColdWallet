"""第三方源码：C1 登记与指纹核对、上游核对（verify-upstream）、重新登记、引入（import）。"""
import os
import re
import subprocess
import tempfile
from awlib.common import NAME_RE, SHA1_RE, TP, fail, git, parse_manifest, tree_hash, write_manifest


# ---------------------------------------------------------------- C1

def cmd_verify_third_party(args):
    release = "--release" in args
    entries = parse_manifest()
    present = sorted(os.listdir(TP)) if os.path.isdir(TP) else []
    ok = True
    allowed_meta = {"MANIFEST.toml", "BINARY_ALLOWLIST", "REVIEW"}
    registered = {e["name"]: e for e in entries}
    if present and not entries and any(p not in allowed_meta for p in present):
        fail("[C1] 失败：third_party 下有内容但没有 MANIFEST.toml")
    for name in present:
        full = os.path.join(TP, name)
        if name in ("MANIFEST.toml", "BINARY_ALLOWLIST"):
            if not os.path.isfile(full) or os.path.islink(full):
                print(f"[C1] {name} 必须是普通文件")
                ok = False
            continue
        if name == "REVIEW":
            for sub in os.listdir(full):
                p = os.path.join(full, sub)
                if not (sub.endswith(".md") and os.path.isfile(p) and not os.path.islink(p)):
                    print(f"[C1] REVIEW 目录只允许 .md 普通文件：{sub}")
                    ok = False
            continue
        if name not in registered:
            print(f"[C1] 未登记的条目：third_party/{name}")
            ok = False
    for name, e in registered.items():
        full = os.path.join(TP, name)
        if os.path.islink(full) or not os.path.isdir(full):
            print(f"[C1] 登记了但不是普通目录：{name}")
            ok = False
            continue
        actual = tree_hash(full)
        if actual != e["tree_sha256"]:
            print(f"[C1] 指纹不符：{name}\n     期望 {e['tree_sha256']}\n     实际 {actual}")
            ok = False
        else:
            print(f"[C1] 一致：{name}")
        reviewed = review_complete(name, e["review"])
        if not reviewed:
            print(f"[C1] {'失败' if release else '提醒'}：{name} 尚未完成人工审查（需两名审查人且 REVIEW/{name}.md 结论为同意）")
            ok = ok and not release
    if not ok:
        fail("[C1] 失败")
    print("[C1] 通过" + ("（发布模式）" if release else "（开发模式：未审查条目只提醒）"))


REVIEW_RE = re.compile(r"^[^;\s]+ \d{4}-\d{2}-\d{2}(; [^;\s]+ \d{4}-\d{2}-\d{2})+$")


def review_complete(name, review_field):
    """发布门槛：MANIFEST 中 review 至少两名审查人（"甲 2026-10-11; 乙 2026-10-12"），
    且 REVIEW/<name>.md 的结论表中"是否同意引入"一栏填写了"同意"。"""
    if not REVIEW_RE.match(review_field):
        return False
    path = os.path.join(TP, "REVIEW", f"{name}.md")
    if not os.path.isfile(path):
        return False
    return any(re.match(r"^\| 是否同意引入 \| 同意 \|", ln) for ln in open(path, encoding="utf-8"))


def export_commit(url, commit, ref, paths, dest):
    """取上游 commit，确认它属于 ref（标签或分支）的历史，导出（可选子集）到 dest。"""
    with tempfile.TemporaryDirectory(prefix="aw-up-") as work:
        git("init", "-q", work)
        r = git("fetch", "-q", "--filter=blob:none", url, f"+{ref}:refs/aw/ref", cwd=work, check=False)
        if r.returncode != 0:
            raise SystemExit(f"无法获取上游引用 {ref}：{r.stderr.decode()[-400:]}")
        r = git("fetch", "-q", url, commit, cwd=work, check=False)
        if r.returncode != 0:
            raise SystemExit(f"上游不存在 commit {commit}（发布包无法追溯到源码）")
        got = git("rev-parse", f"{commit}^{{commit}}", cwd=work).stdout.decode().strip()
        if got != commit:
            raise SystemExit(f"commit 不一致：{got}")
        r = git("merge-base", "--is-ancestor", commit, "refs/aw/ref", cwd=work, check=False)
        if r.returncode != 0:
            raise SystemExit(f"commit {commit} 不在上游 {ref} 的历史中（可能来自 fork）")
        info = os.path.join(work, ".git", "info")
        os.makedirs(info, exist_ok=True)
        with open(os.path.join(info, "attributes"), "w") as f:
            f.write("* -export-ignore -export-subst -text -eol -ident -filter -working-tree-encoding\n")
        cmd = ["git", "-C", work, "archive", "--format=tar", commit]
        if paths:
            cmd += ["--"] + paths
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise SystemExit(f"导出失败（路径不存在？）：{r.stderr.decode()[-300:]}")
        os.makedirs(dest, exist_ok=False)
        subprocess.run(["tar", "-x", "-C", dest], input=r.stdout, check=True)
        if os.path.exists(os.path.join(dest, ".gitmodules")):
            print(f"警告：{url} 含子模块，子模块内容未导入")


def cmd_verify_upstream(args):
    entries = parse_manifest()
    names = set(args) if args else {e["name"] for e in entries}
    ok = True
    for e in entries:
        if e["name"] not in names:
            continue
        with tempfile.TemporaryDirectory(prefix="aw-verify-") as tmp:
            dest = os.path.join(tmp, "src")
            paths = e.get("paths", "").split() if e.get("paths") else []
            export_commit(e["upstream"], e["commit"], e["ref"], paths, dest)
            fresh = tree_hash(dest)
        local = tree_hash(os.path.join(TP, e["name"]))
        if fresh == local == e["tree_sha256"]:
            print(f"[上游] 一致：{e['name']} @ {e['commit'][:12]}（{e['ref']}）")
        else:
            print(f"[上游] 不一致：{e['name']}\n  上游重新导出 {fresh}\n  本地目录     {local}\n  MANIFEST     {e['tree_sha256']}")
            ok = False
    if not ok:
        fail("[上游] 失败")


def cmd_rebaseline(args):
    """仅在 tree-hash 算法变更后使用：重新从上游导出，与本地逐一比对后，用新算法更新 MANIFEST。"""
    entries = parse_manifest()
    for e in entries:
        with tempfile.TemporaryDirectory(prefix="aw-rebase-") as tmp:
            dest = os.path.join(tmp, "src")
            paths = e.get("paths", "").split() if e.get("paths") else []
            export_commit(e["upstream"], e["commit"], e["ref"], paths, dest)
            fresh = tree_hash(dest)
        local = tree_hash(os.path.join(TP, e["name"]))
        if fresh != local:
            fail(f"[重建] 本地与上游不一致，拒绝更新：{e['name']}")
        e["tree_sha256"] = fresh
        print(f"[重建] {e['name']}：{fresh}")
    write_manifest(entries)


def cmd_import(args):
    if len(args) < 5:
        fail("用法：import <名称> <上游 https URL> <40 位 commit> <refs/tags/… 或 refs/heads/…> <许可证> [路径…]")
    name, url, commit, ref, license_ = args[:5]
    paths = args[5:]
    if not NAME_RE.match(name):
        fail("名称只允许小写字母、数字、. _ -，且不超过 64 个字符")
    if not url.startswith("https://") or any(c in url for c in ' "\\'):
        fail("只接受 https 上游地址")
    if not SHA1_RE.match(commit):
        fail("commit 必须是完整的 40 位十六进制")
    if not re.fullmatch(r"refs/(tags|heads)/[A-Za-z0-9._/+-]+", ref):
        fail("必须给出上游引用 refs/tags/<标签> 或 refs/heads/<分支>，用来证明 commit 来自上游而非 fork")
    if any(not re.fullmatch(r"[A-Za-z0-9._/-]+", p) or ".." in p.split("/") for p in paths):
        fail("子集路径不合法")
    if '"' in license_ or "\\" in license_:
        fail("许可证字段不合法")
    dest = os.path.join(TP, name)
    if os.path.lexists(dest):
        fail(f"{dest} 已存在；升级请先移走旧目录并在审查记录中说明（规则 R6）")
    entries = parse_manifest()
    export_commit(url, commit, ref, paths, dest)
    th = tree_hash(dest)
    import datetime
    entries.append({"name": name, "upstream": url, "ref": ref, "commit": commit, "license": license_,
                    **({"paths": " ".join(paths)} if paths else {}), "tree_sha256": th,
                    "imported_at": datetime.date.today().isoformat(), "review": "PENDING"})
    write_manifest(entries)
    print(f"[导入] {name} @ {commit[:12]}（{ref}）指纹 {th}")
