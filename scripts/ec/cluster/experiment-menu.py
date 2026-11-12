#!/usr/bin/env python3
"""中文实验选择入口；选择完成后 exec 正式脚本，不保留菜单进程。"""
import argparse
from pathlib import Path
import re
import shlex
import sys
import os


LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
SAMPLES = {
    "1": ("kv112", "112 KiB 短尾数据"),
    "2": ("multi", "1 MiB 多分块数据"),
    "3": ("max16", "10 MiB、十六分块边界数据"),
}
STRATEGIES = {
    "1": ("central", "集中式修复"),
    "2": ("pipeline", "客户端分块流水线修复"),
    "3": ("helper", "原生 helper 链式修复"),
}
CHOICES = (
    ("1", "查看现有服务状态"),
    ("2", "准备确定性实验数据"),
    ("3", "运行一个指定策略实验"),
    ("4", "运行三种策略 × 单片/双片的六组实验"),
    ("5", "运行短尾与十六分块的两个边界实验"),
    ("6", "按原日志恢复一次未完成操作"),
    ("7", "按原日志释放远端读取保护"),
    ("8", "从已发布结果发起一次新读取"),
    ("9", "核对已有读回文件的字节与摘要"),
    ("10", "EC 文件：读写、追加、截断、同步与恢复"),
    ("0", "退出"),
)


def choose(title, options):
    print("\n" + title)
    for key, value in options.items():
        print(f"  {key}. {value[1]}")
    while True:
        value = input("输入编号：").strip()
        if value in options:
            return options[value][0]
        print("请输入列出的编号；尚未执行任何命令。")


def label(title):
    while True:
        value = input(title).strip()
        if LABEL.fullmatch(value):
            return value
        print("使用 1–64 个英文字母、数字、下划线或短横线，首字符为字母或数字。")


def existing_path(title):
    while True:
        value = input(title).strip()
        try:
            path = Path(value).expanduser()
            if value and path.is_absolute() and path.is_dir() and path == path.resolve(strict=True):
                return str(path)
        except (OSError, RuntimeError):
            pass
        print("请输入已有日志目录的完整绝对路径；不创建、重命名或替换目录。")


def selection(root, script_directory):
    print("\n3FS EC 本机功能实验")
    print(f"实验根目录：{root}")
    print("以下操作使用现有服务；服务启动、停止和重启由独立监督进程管理。")
    print("替换一片/两片不等于停止存储节点；这里不作集群性能或故障域结论。")
    for key, text in CHOICES:
        print(f"  {key}. {text}")
    while True:
        action = input("选择操作：").strip()
        if action in dict(CHOICES):
            break
        print("请输入列出的编号。")
    if action == "0":
        return None
    if action == "1":
        return [sys.executable, "-B", str(script_directory / "native-v2.py"), "status", "--root", str(root)]
    if action == "10":
        return file_selection(root, script_directory)
    command = [sys.executable, "-B", str(script_directory / "experiment-runner.py"), "--root", str(root)]
    if action == "2":
        return command + ["inputs"]
    if action in ("3", "4", "5"):
        print("新实验须使用未占用的名称。已有名称不会覆盖；失败后应按原日志恢复。")
        name = label("实验名称：")
        if action == "4":
            return command + ["matrix", "--label", name]
        if action == "5":
            return command + ["boundaries", "--label", name]
        strategy = choose("修复策略", STRATEGIES)
        count = choose("替换片数", {"1": ("1", "单片"), "2": ("2", "双片")})
        sample = choose("输入数据", SAMPLES)
        return command + ["case", "--label", name, "--strategy", strategy, "--replacements", count, "--sample", sample]
    if action == "8":
        print("此操作只发起新读取，不能单独证明服务已重启；重启证据须另行核对。")
        source = existing_path("已发布写入或修复日志目录：")
        name = label("新读取名称：")
        sample = choose("与源操作一致的输入数据", SAMPLES)
        return command + ["after-restart", "--source-run", source, "--read-label", name, "--sample", sample]
    run = existing_path("原生操作日志目录：")
    name = {"6": "resume", "7": "release", "9": "verify-read"}[action]
    command += [name, "--run-dir", run]
    if action != "7":
        command += ["--sample", choose("与原操作一致的输入数据", SAMPLES)]
    return command


def file_selection(root, script_directory):
    action = choose("EC 文件操作（要求部署时选择 --file-api）", {
        "1": ("create", "创建文件并打开读写会话"),
        "2": ("pwrite", "按字节偏移写入"),
        "3": ("read", "按字节范围读取"),
        "4": ("truncate", "截断或扩展文件"),
        "5": ("append", "在服务端原子确定的末尾追加"),
        "6": ("fsync", "建立持久性屏障"),
        "7": ("repair", "选择策略与源分片，修复一个文件条带"),
        "8": ("manage", "恢复、查询或终结已有操作；关闭会话"),
    })
    if action == "manage":
        category = choose("选择原操作类型", {
            "1": ("session", "文件会话"), "2": ("write", "局部写入"),
            "3": ("read", "快照读取"), "4": ("truncate", "截断或扩展"),
            "5": ("append", "原子追加"), "6": ("sync", "持久性屏障"),
            "7": ("repair", "条带修复"),
        })
        actions = {
            "session": [("resume-open", "继续原打开请求"), ("close", "关闭原会话")],
            "write": [("query", "查询"), ("resume", "继续"), ("seal", "固定已确认前缀，放弃其余部分")],
            "read": [("resume-read", "继续读取并使用新输出"), ("release-read", "释放远端读取保护")],
            "truncate": [("query-truncate", "查询"), ("resume-truncate", "继续"),
                         ("close-truncate-debt", "终结；尚未发布的计划会被放弃")],
            "append": [("query-append", "查询"), ("resume-append", "继续"),
                       ("seal-append", "固定已确认前缀，放弃未写尾部")],
            "sync": [("resume-fsync", "重放原持久性屏障")],
            "repair": [("query-repair", "查询发布和清理状态"), ("resume-repair", "继续"),
                       ("close-repair-debt", "终结并清理；尚未发布的修复会被取消")],
        }
        action = choose("选择处理方式", {str(i + 1): value for i, value in enumerate(actions[category])})
    command = [sys.executable, "-B", str(script_directory / "file-command.py"), "--root", str(root), action]
    if action not in ("create", "pwrite", "read", "truncate", "append", "fsync", "repair"):
        if action in ("seal", "seal-append", "close-truncate-debt", "close-repair-debt"):
            print("此操作会终结原操作；尚未发布的部分不能再用原操作继续写入。")
        command += ["--run-dir", existing_path("原操作日志目录的绝对路径：")]
        if action == "resume-read":
            name = label("本次新输出名称：")
            command += ["--output", str(root / "client/outputs" / ("read-" + name + ".bin"))]
        return command
    name = label("本次新操作名称：")
    command += ["--run-dir", str(root / "client/runs" / (action + "-" + name))]
    if action == "create":
        return command + ["--path", input("3FS 中新文件的绝对路径（例如 /ec-lab/file-a）：").strip()]
    command += ["--session", existing_path("已打开会话的原日志目录：")]
    if action == "repair":
        print("会话须同时具有读写权限。目标选择本身不等于真实节点离线。")
        return command + ["--strategy", choose("修复策略", STRATEGIES),
                          "--stripe", input("文件条带索引：").strip(),
                          "--targets", input("待重建分片（1或2个，0至11，逗号分隔）：").strip(),
                          "--sources", input("固定10个源分片的顺序（不得含待重建片，逗号分隔）：").strip(),
                          "--window", choose("在途窗口", {str(n): (str(n), str(n)) for n in range(1, 5)})]
    if action == "fsync":
        print("先恢复或终结其他未完成操作；屏障不会代替它们执行写入。")
        return command
    if action == "truncate":
        return command + ["--length", input("新文件长度（字节，十进制整数）：").strip()]
    if action == "append":
        return command + ["--input", input("本机输入文件的绝对路径：").strip()]
    command += ["--offset", input("字节偏移（十进制整数）：").strip()]
    if action == "pwrite":
        return command + ["--input", input("本机输入文件的绝对路径：").strip()]
    return command + ["--length", input("最大读取字节数：").strip(),
                      "--output", str(root / "client/outputs" / ("read-" + name + ".bin"))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="已有 Linux 原生实验根目录")
    parser.add_argument("--print-only", action="store_true", help="仅显示所选命令，不执行")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("在 Linux 实验环境中运行；Windows 用户请使用已配置的 WSL。")
    if not sys.stdin.isatty():
        parser.error("交互菜单需要终端；自动化请直接使用 experiment-runner.py。")
    root = args.root.expanduser()
    if not root.is_absolute() or not root.is_dir() or root != root.resolve(strict=True):
        parser.error("--root 必须是已有、无符号链接重定向的绝对目录。")
    scripts = Path(__file__).resolve().parent
    command = selection(root, scripts)
    if command is None:
        return 0
    target = Path(command[2])
    if not target.is_file():
        parser.error(f"缺少正式脚本：{target}。请把菜单安装在原生脚本同一目录。")
    print("\n对应命令（可复制到终端复现）：")
    print(shlex.join(command))
    if args.print_only:
        print("仅显示命令，本次未运行实验。")
        return 0
    print("现在转交正式脚本；结果与失败记录由正式脚本保存。", flush=True)
    # Replacement preserves PID, environment, cwd and inherited descriptors.
    # There is no shell, sampler, child watcher or second menu process during
    # the experiment. Formal validation and signal/ownership handling remain
    # entirely in the selected existing script.
    os.execv(sys.executable, command)
    raise AssertionError("execv returned")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, KeyboardInterrupt):
        print("\n已取消选择，未派发实验。", file=sys.stderr)
        raise SystemExit(130)
    except OSError as error:
        print(f"无法启动正式脚本：{error}", file=sys.stderr)
        raise SystemExit(2)
