"""在新会话中运行一个命令（tools/cargo-sb 用）：没有控制终端；命令结束后，结束同一会话中残留的全部进程。

安全复核四 H1：构建脚本可以在后台留下进程，等检查做完再改 target/ 里的产物。
正常的 Cargo 构建结束时不会留下任何进程，所以发现残留就视为构建失败。
局限：自己调用 setsid() 另建会话的进程不在此列——所以正式构建还要把产物拷到沙箱写不到的
build/lib/ 再核验、再链接（见 tools/ios/build-*.sh）。
用法：python3 -I tools/sb-session.py <程序绝对路径> [参数...]
"""
import os
import signal
import subprocess
import sys
import time


def session_members(sid):
    r = subprocess.run(["/bin/ps", "-axo", "pid="], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("[cargo-sb] ps 失败，无法检查残留进程")
    members = []
    for tok in r.stdout.split():
        pid = int(tok)
        try:
            if os.getsid(pid) == sid:
                members.append(pid)
        except (ProcessLookupError, PermissionError):
            continue  # 进程已退出，或属于其他用户（不可能是我们的会话成员）
    return members


def reap(sid):
    """结束会话 sid 中的全部进程，返回曾经残留的进程号。"""
    seen = set()
    for _ in range(10):
        members = session_members(sid)
        if not members:
            return sorted(seen)
        seen.update(members)
        for pid in members:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
    raise SystemExit(f"[cargo-sb] 无法结束残留进程：{session_members(sid)}")


def main():
    if len(sys.argv) < 2 or not os.path.isabs(sys.argv[1]):
        raise SystemExit("用法：sb-session.py <程序绝对路径> [参数...]")
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.execv(sys.argv[1], sys.argv[1:])
        finally:
            os._exit(127)
    def on_signal(signum, _frame):
        # 复核五 M4：Ctrl-C 只会发给前台进程组，子会话收不到；这里负责结束整个子会话
        reap(pid)
        sys.exit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, on_signal)
    try:
        _, status = os.waitpid(pid, 0)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    rc = os.waitstatus_to_exitcode(status)
    leftovers = reap(pid)  # setsid 后会话号 = 该子进程号
    if leftovers:
        print(f"[cargo-sb] 构建结束后会话中仍有进程（已强制结束：{leftovers}）。"
              "构建时代码在后台启动了程序，视为构建失败。", file=sys.stderr)
        sys.exit(1)
    sys.exit(rc)


if __name__ == "__main__":
    main()
