"""产物检查：C4 导入白名单、受限调用点、原始字节与重定位检查，C5 链接库白名单。"""
import os
import re
import subprocess
from awlib.common import ROOT, fail, read_list


# ---------------------------------------------------------------- C4 / C5

DENY_EXACT = {
    "_dlopen", "_dlsym", "_dlvsym", "_NSClassFromString", "_NSSelectorFromString", "_objc_getClass",
    "_objc_lookUpClass", "_objc_getRequiredClass", "_syscall", "_socket", "_connect", "_connectx",
    "_bind", "_listen", "_accept", "_send", "_sendto", "_sendmsg", "_recv", "_recvfrom", "_recvmsg",
    "_getaddrinfo", "_gethostbyname", "_posix_spawn", "_fork", "_execve", "_system", "_popen",
    # 复核四 H2 之后，编译器运行时的系统版本检查由我们自己的 Rust 实现替代（决策 D17），不再需要
    "_fopen",
}
DENY_SUBSTR = ("URLSession", "NSURLConnection", "NWConnection", "NWListener", "nw_", "CFSocket",
               "CFStream", "CFHTTP", "CFNetwork", "DNSService", "SCNetworkReachability",
               "MultipeerConnectivity", "CoreBluetooth", "UIPasteboard", "WKWebView", "_res_9_")


# SwiftUI 内联代码的运行时提示（@Environment 用在 View 之外时）。这是唯一允许的系统日志用法：
# 格式串固定，只含类型名，不含任何数据（威胁 T10）。
OSLOG_ALLOWED_FORMATS = {
    "Accessing Environment<%s>'s value outside of being installed on a View. "
    "This will always read the default value and will not update.",
}


_DISASM = {}


def disasm(f):
    if f not in _DISASM:
        r = subprocess.run(["xcrun", "objdump", "--macho", "-d", f], capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout:
            raise SystemExit(f"objdump 失败：{f}")
        _DISASM[f] = r.stdout.splitlines()
    return _DISASM[f]


def disasm_violations(f):
    """静态检查的补充（不是完备证明，见 docs/02 R3 的说明）：
    - 任何 svc/hvc/smc（绕过 libSystem 直接系统调用）
    - 禁用符号除"直接 bl 调用桩"以外的任何引用（取函数指针、读 GOT）
    - 用 adrp+add / adr 计算出禁用符号桩地址"""
    lines = disasm(f)
    bad = []
    stub_addr = {}
    for line in lines:
        m = re.search(r"\bbl\s+0x([0-9a-f]+)\s*; symbol stub for: (_\w+)$", line)
        if m and m.group(2) in DENY_EXACT:
            stub_addr[int(m.group(1), 16)] = m.group(2)
    regs = {}
    for line in lines:
        ins = line.split("\t")
        if re.search(r"\t(svc|hvc|smc)\t", line):
            bad.append(f"直接系统调用指令：{line.strip()}")
        for sym in DENY_EXACT:
            if re.search(re.escape(sym) + r"\b", line) and not re.search(r"\bbl\s+0x[0-9a-f]+\s*; symbol stub for: " + re.escape(sym) + r"$", line):
                bad.append(f"非直接调用的引用 {sym}：{line.strip()}")
        m = re.search(r"\tadrp\t(x\d+), \d+ ; 0x([0-9a-f]+)", line)
        if m:
            regs[m.group(1)] = int(m.group(2), 16)
            continue
        m = re.search(r"\tadd\t(x\d+), (x\d+), #0x([0-9a-f]+)", line)
        if m and m.group(2) in regs:
            addr = regs[m.group(2)] + int(m.group(3), 16)
            if addr in stub_addr:
                bad.append(f"计算出禁用符号桩地址 {stub_addr[addr]}：{line.strip()}")
        m = re.search(r"\tadr\t(x\d+), .*; 0x([0-9a-f]+)", line)
        if m and int(m.group(2), 16) in stub_addr:
            bad.append(f"计算出禁用符号桩地址：{line.strip()}")
        del ins
    return bad


# __TEXT 段中允许出现的节（标准编译器/链接器产物）。任何其他节都可能藏有可执行代码（P1 安全复核三 H3）。
TEXT_SECTIONS_ALLOWED = {
    "__text", "__stubs", "__auth_stubs", "__objc_stubs", "__stub_helper", "__const", "__cstring",
    "__constg_swiftt", "__eh_frame", "__gcc_except_tab", "__unwind_info", "__oslogstring", "__ustring",
    "__objc_classname", "__objc_methlist", "__objc_methname", "__objc_methtype", "__info_plist",
    "__swift5_assocty", "__swift5_builtin", "__swift5_capture", "__swift5_entry", "__swift5_fieldmd",
    "__swift5_mpenum", "__swift5_proto", "__swift5_protos", "__swift5_reflstr", "__swift5_typeref",
    "__swift5_types", "__swift5_acfuncs", "__swift_as_entry", "__swift_as_ret", "__swift_as_cont",
    "__swift5_replace", "__swift5_replac2",
}
# Swift 异步函数的入口 / 返回 / 续体表（D36）：每项是指向代码的 32 位相对指针，必须全部落在 __text 内
SWIFT_ASYNC_POINTER_TABLES = {"__swift_as_entry", "__swift_as_ret", "__swift_as_cont"}
CODE_SECTIONS = {"__text", "__stubs", "__auth_stubs", "__objc_stubs", "__stub_helper"}
# 只允许通过 GOT 槽位绑定的受限导入（不允许出现在数据区的函数指针里）
RESTRICTED_BIND = {"__os_log_impl"}


def macho_sections(f):
    """解析 otool -l：返回 ([(段名, 节名, 虚拟地址, 大小, 文件偏移)], {段名: 初始保护属性})。"""
    r = subprocess.run(["otool", "-l", f], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        raise SystemExit(f"otool -l 失败：{f}")
    secs, segs, cur, segname = [], {}, None, None
    for line in r.stdout.splitlines():
        t = line.split()
        if not t:
            continue
        if t[0] == "sectname" and len(t) == 2:
            cur = {"sectname": t[1]}
            secs.append(cur)
        elif t[0] in ("cmd", "Load"):
            cur, segname = None, None
        elif cur is not None and t[0] in ("segname", "addr", "size", "offset") and len(t) == 2:
            cur[t[0]] = t[1]
        elif cur is None and t[0] == "segname" and len(t) == 2:
            segname = t[1]
        elif cur is None and t[0] == "initprot" and len(t) == 2 and segname:
            segs[segname] = int(t[1], 16)
    out = [(c["segname"], c["sectname"], int(c["addr"], 16), int(c["size"], 16), int(c["offset"]))
           for c in secs]
    if not out or "__TEXT" not in segs:
        raise SystemExit(f"无法解析 Mach-O 节表：{f}")
    return out, segs


def _sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def branch_target(w, pc):
    """直接跳转指令（b/bl、b.cond、cbz/cbnz、tbz/tbnz）的目标地址；其他指令返回 None。"""
    if (w & 0x7C000000) == 0x14000000:
        return pc + _sext(w & 0x3FFFFFF, 26) * 4
    if (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000:
        return pc + _sext((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0x7E000000) == 0x36000000:
        return pc + _sext((w >> 5) & 0x3FFF, 14) * 4
    return None


SVC_EXACT = (0xD4001001, 0xD4000001)  # svc #0x80、svc #0：Darwin 系统调用的常见写法


def is_svc(w):
    return (w & 0xFFE0001F) in (0xD4000001, 0xD4000002, 0xD4000003)


def sets_x16(w):
    """movz / movn / movk 写 x16 或 w16（Darwin 用 x16 传系统调用号）。"""
    return (w & 0x1F80001F) == 0x12800010


def data_svc_violations(data, secs):
    """非代码节（如 __TEXT,__const）里的字节同样可执行（复核四 H3）。普通数据里偶有字节恰好符合 svc
    的编码掩码（实测签名机 __const 中 11 处），所以只报两种情况：Darwin 常用的确切编码；或者前 3 个字
    之内有设置 x16 的指令。这仍是启发式，不是证明（见 docs/02「C4 做什么、不做什么」）。"""
    bad = []
    for seg, sect, addr, size, off in secs:
        if seg != "__TEXT" or sect in CODE_SECTIONS:
            continue
        start = off + (-off % 4)
        words = [int.from_bytes(data[k:k + 4], "little") for k in range(start, off + size - 3, 4)]
        for i, w in enumerate(words):
            if w in SVC_EXACT or (is_svc(w) and any(sets_x16(x) for x in words[max(0, i - 3):i])):
                bad.append(f"{sect} 0x{addr + (start - off) + 4 * i:x}：数据中出现系统调用指令编码")
    return bad


def code_violations(data, secs):
    """原始字节扫描（不依赖反汇编器）：代码节里不得有 svc/hvc/smc；直接跳转只能落在代码节内。"""
    bad = []
    code = [(a, a + n) for seg, sect, a, n, _ in secs if seg == "__TEXT" and sect in CODE_SECTIONS]
    for seg, sect, addr, size, off in secs:
        if seg != "__TEXT" or sect not in CODE_SECTIONS:
            continue
        for i in range(0, size - 3, 4):
            w = int.from_bytes(data[off + i:off + i + 4], "little")
            if is_svc(w):
                bad.append(f"{sect} 0x{addr + i:x}：直接系统调用指令（svc/hvc/smc）")
            t = branch_target(w, addr + i)
            if t is not None and not any(lo <= t < hi for lo, hi in code):
                bad.append(f"{sect} 0x{addr + i:x}：跳转到代码节以外 0x{t:x}（数据区中藏代码？）")
    return bad


def fixup_violations(f, secs):
    """dyld 绑定检查：受限符号只能出现在 GOT 槽位、且各一次；禁用符号不得被绑定；
    数据区不得保存指向桩函数的指针（绕过 bl 直接调用检查的另一种方式）。"""
    r = subprocess.run(["xcrun", "dyld_info", "-fixups", f], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return ["dyld_info 失败"]
    stubs = [(a, a + n) for seg, sect, a, n, _ in secs if seg == "__TEXT" and sect in CODE_SECTIONS - {"__text"}]
    bad, binds = [], {}
    for line in r.stdout.splitlines():
        t = line.split()
        if len(t) < 5 or not t[2].startswith("0x"):
            continue
        if t[3] == "bind":
            binds.setdefault(t[4].split("/", 1)[-1], []).append(f"{t[0]},{t[1]}")
        elif t[3] == "rebase":
            v = int(t[4], 16)
            if any(lo <= v < hi for lo, hi in stubs):
                bad.append(f"数据区 {t[0]},{t[1]} {t[2]} 保存了桩函数地址 0x{v:x}")
        else:
            bad.append(f"未知的重定位类型：{line.strip()}")
    if not binds:
        bad.append("没有解析到任何绑定（输出格式变了？检查无效）")
    for sym in sorted(DENY_EXACT | RESTRICTED_BIND):
        locs = binds.get(sym, [])
        if not locs:
            continue
        if sym not in RESTRICTED_BIND:
            bad.append(f"禁用符号 {sym} 被绑定：{locs}")
        elif len(locs) > 1 or any(loc.split(",")[1] not in ("__got", "__auth_got") for loc in locs):
            bad.append(f"受限符号 {sym} 绑定在 GOT 以外或不止一处（数据区函数指针？）：{locs}")
    return bad


def section_violations(f):
    with open(f, "rb") as fh:
        data = fh.read()
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return ["通用（fat）二进制：请对每个架构单独检查"]
    secs, segs = macho_sections(f)
    bad = [f"非 __TEXT 段具有执行权限：{name}" for name, prot in segs.items() if prot & 0x4 and name != "__TEXT"]
    bad += [f"__TEXT 中出现非标准节：{sect}" for seg, sect, *_ in secs
            if seg == "__TEXT" and sect not in TEXT_SECTIONS_ALLOWED]
    return (bad + code_violations(data, secs) + data_svc_violations(data, secs)
            + async_table_violations(data, secs) + fixup_violations(f, secs))


def async_table_violations(data, secs):
    """__swift_as_* 只能是相对指针表：长度为 4 的倍数，每项指向 __text 内部（不是可执行代码，也不能指到别处）。"""
    text = [(a, a + n) for seg, sect, a, n, _ in secs if seg == "__TEXT" and sect == "__text"]
    bad = []
    for seg, sect, addr, size, off in secs:
        if seg != "__TEXT" or sect not in SWIFT_ASYNC_POINTER_TABLES:
            continue
        if size % 4:
            bad.append(f"{sect} 长度不是 4 的倍数（{size}）")
            continue
        for i in range(0, size, 4):
            rel = int.from_bytes(data[off + i:off + i + 4], "little", signed=True)
            t = addr + i + rel
            if not any(lo <= t < hi for lo, hi in text):
                bad.append(f"{sect} 0x{addr + i:x}：相对指针指向 __text 以外 0x{t:x}")
    return bad


_BRANCH_TARGETS = {}


def branch_targets(f):
    """反汇编中所有直接跳转目标（用来判断"字面量装载 → 调用"之间有没有别处跳进来）。"""
    if f not in _BRANCH_TARGETS:
        ts = set()
        for line in disasm(f):
            m = re.search(r"\t(?:b|bl|b\.\w+|cbn?z|tbn?z)\t(?:[wx]\d+, )?(?:#0x[0-9a-f]+, )?0x([0-9a-f]+)", line)
            if m:
                ts.add(int(m.group(1), 16))
        _BRANCH_TARGETS[f] = ts
    return _BRANCH_TARGETS[f]


def _addr(line):
    m = re.match(r"\s*([0-9a-f]+):", line)
    return int(m.group(1), 16) if m else None


# 复核五：ret / eret 等没有操作数的指令后面没有制表符
FLOW_INSN = re.compile(r"\t(?:b|bl|blr|blraa|blrab|blraaz|blrabz|br|braa|brab|braaz|brabz|ret|retaa|retab"
                       r"|b\.\w+|cbn?z|tbn?z|svc|hvc|smc|eret)(?:\t|\s*$)")


def call_arg_literals(f, stub, reg):
    """对每个直接调用 stub 的位置，确定参数寄存器 reg（如 x1）在调用时的值是否为某个字符串字面量。
    严格规则（P1 安全复核三：附近出现字面量不等于参数就是它）：
    - 向前找到最近一条写 reg 的指令，它必须是 `add reg, reg, #imm ; literal pool for: "..."`，
      且前一条是 `adrp reg`
    - 从该 add 之后到调用之间，没有任何其他指令提到 reg/同号 w 寄存器，也没有跳转目标落在这段区间
    - 这段区间内不得有任何跳转、调用或返回指令（被调函数会隐式改写参数寄存器，复核四 H2）
    不满足时该调用点记为 None（无法静态确定 → 检查失败）。"""
    lines = disasm(f)
    n = reg[1:]
    mention = re.compile(r"\b[xw]" + n + r"\b")
    targets = branch_targets(f)
    sites = []
    for i, line in enumerate(lines):
        if not re.search(r"\bbl\s+0x[0-9a-f]+\s*; symbol stub for: " + re.escape(stub) + r"$", line):
            continue
        val = None
        call_at = _addr(line)
        for j in range(i - 1, max(0, i - 16) - 1, -1):
            ins = lines[j]
            if FLOW_INSN.search(ins):
                break
            if not mention.search(ins.split(";")[0]):
                continue
            m = re.search(r"\tadd\t" + reg + r", " + reg + r', #0x[0-9a-f]+ ; literal pool for: "(.*)"$', ins)
            prev = lines[j - 1] if j > 0 else ""
            here = _addr(ins)
            if (m and re.search(r"\tadrp\t" + reg + r", ", prev) and here is not None and call_at is not None
                    and not any(here < t <= call_at for t in targets)):
                val = m.group(1)
            break
        sites.append(val)
    return sites


def check_restricted_calls(f, imports):
    """系统日志是唯一允许的受限导入：每个调用点的格式串必须是允许的字面量。"""
    if "__os_log_impl" not in imports:
        return True
    sites = call_arg_literals(f, "__os_log_impl", "x3")
    bad = [v for v in sites if v not in OSLOG_ALLOWED_FORMATS]
    if not sites or bad:
        print(f"[C4] 系统日志格式串不在允许集合内或无法静态确定（可能记录敏感数据）：{bad or '无调用点'}")
        return False
    print(f"[C4] __os_log_impl：{len(sites)} 个调用点的格式串均为允许的字面量")
    return True


def macho_files(path):
    if os.path.isfile(path):
        return [path]
    found = []
    for d, _dn, fns in os.walk(path):
        for n in fns:
            p = os.path.join(d, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                magic = f.read(4)
            if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                found.append(p)
    return found


def cmd_check_binary(args):
    import_allow = read_list("signer-imports.allow")
    lib_allow = read_list("signer-libs.allow")
    ok, files = True, []
    for a in args:
        fs = macho_files(a)
        if not fs:
            fail(f"[C4] 找不到 Mach-O 文件：{a}")
        files += fs
    for f in files:
        r = subprocess.run(["nm", "-u", "-j", f], capture_output=True, text=True)
        imports = sorted({s.strip() for s in r.stdout.splitlines() if s.strip()})
        if r.returncode != 0 or not imports:
            print(f"[C4] nm 失败或没有读到任何导入符号：{f}")
            ok = False
            continue
        restricted_ok = check_restricted_calls(f, imports)
        ok = ok and restricted_ok
        dv = disasm_violations(f) + section_violations(f)
        if dv:
            print(f"[C4] 反汇编检查不通过：{f}\n    " + "\n    ".join(dv[:20]))
            ok = False
        denied = [s for s in imports
                  if s in DENY_EXACT or any(x in s for x in DENY_SUBSTR)]
        unknown = [s for s in imports if s not in import_allow]
        if denied:
            print(f"[C4] 禁用的导入：{f}\n    " + "\n    ".join(denied))
            ok = False
        if unknown:
            print(f"[C4] 不在白名单的导入（需审查后加入 tools/checks/signer-imports.allow）：{f}\n    " + "\n    ".join(unknown))
            ok = False
        if not denied and not unknown:
            print(f"[C4] 导入白名单：符合（{os.path.relpath(f, ROOT)}，{len(imports)} 个导入）")
        r = subprocess.run(["otool", "-L", f], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[C5] otool 失败：{f}")
            ok = False
            continue
        libs = [ln.strip().split(" (")[0] for ln in r.stdout.splitlines()[1:] if ln.strip()]
        bad = [lib for lib in libs if lib not in lib_allow]
        if bad:
            print(f"[C5] 不在白名单的链接库：{f}\n    " + "\n    ".join(bad))
            ok = False
        else:
            print(f"[C5] 通过：{os.path.relpath(f, ROOT)}（{len(libs)} 个链接库）")
    if not ok:
        fail("[C4/C5] 失败")
