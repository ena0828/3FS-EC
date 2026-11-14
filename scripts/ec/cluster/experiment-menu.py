#!/usr/bin/env python3
"""中文实验选择入口；选择完成后 exec 正式脚本，不保留菜单进程。"""
import argparse
import json
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
    ("11", "EC 文件：运行完整 basic / repair 功能验收"),
    ("12", "已挂载 mode4：USRBIO 准备或原记录验证"),
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


def label(title, maximum=64):
    while True:
        value = input(title).strip()
        if LABEL.fullmatch(value) and len(value) <= maximum:
            return value
        print(f"使用 1–{maximum} 个英文字母、数字、下划线或短横线，首字符为字母或数字。")


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
    if action == "11":
        return file_acceptance_selection(root, script_directory)
    if action == "12":
        return usrbio_selection(root, script_directory)
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
        delivery = []
        if strategy == "helper":
            delivery = ["--delivery", choose("Helper 结果交付方式", {
                "1": ("return", "回传客户端，由客户端写入目标"),
                "2": ("direct", "末站直接写入目标，客户端接收小回执"),
            })]
        count = choose("替换片数", {"1": ("1", "单片"), "2": ("2", "双片")})
        sample = choose("输入数据", SAMPLES)
        return command + ["case", "--label", name, "--strategy", strategy, *delivery,
                          "--replacements", count, "--sample", sample]
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
        strategy = choose("修复策略", STRATEGIES)
        delivery = []
        if strategy == "helper":
            delivery = ["--delivery", choose("Helper 结果交付方式", {
                "1": ("return", "回传客户端，由客户端写入目标"),
                "2": ("direct", "末站直接写入目标，客户端接收小回执"),
            })]
        return command + ["--strategy", strategy, *delivery,
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



def json_object(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"需要 JSON 对象：{path}")
    return value


def file_api_profile(root):
    manifest = json_object(root / "cluster.json")
    profiles = {"native-gc-local-1-storage-12-targets", "native-gc-local-12-storage-12-targets"}
    if (manifest.get("root") != str(root) or manifest.get("file_api") is not True
            or type(manifest.get("profile")) is not str or manifest["profile"] not in profiles):
        raise ValueError("所选目录必须是显式 --file-api 准备的原生 GC 实验包；菜单不会修改 profile。")
    print(f"既定部署 profile：{manifest['profile']}；file_api=true")
    print("这里只做功能验收；服务及挂载必须由原监督入口另行管理。")


def input_file(title):
    while True:
        value = input(title).strip()
        try:
            path = Path(value).expanduser()
            if value and path.is_absolute() and path.is_file() and path == path.resolve(strict=True):
                return path
        except (OSError, RuntimeError):
            pass
        print("请输入已有普通文件的完整绝对路径，不使用符号链接重定向。")


def new_path(title):
    while True:
        value = input(title).strip()
        try:
            path = Path(value).expanduser()
            if (value and path.is_absolute() and path.name not in ("", ".", "..")
                    and path.parent.is_dir() and path.parent == path.parent.resolve(strict=True)
                    and not path.exists() and not path.is_symlink()):
                return path
        except (OSError, RuntimeError):
            pass
        print("请输入未占用的绝对路径；父目录须已存在且无符号链接。菜单不会创建目录。")


def file_acceptance_selection(root, scripts):
    file_api_profile(root)
    phase = choose("选择固定功能验收流程", {
        "1": ("basic", "basic：局部写、读回、截断/扩展、追加、同步及恢复"),
        "2": ("repair", "repair：central / pipeline / helper × 单片 / 双片"),
    })
    print("输入为正式脚本生成的确定性 SHAKE256 合成数据，不读取自选数据集。")
    if phase == "basic":
        print("basic 固定 shard=65536 字节，覆盖跨条带与短尾；输入配方及摘要另存原报告。")
    else:
        print("repair 固定 shard=131072 字节、window=2；源分片和顺序由正式脚本固定。")
        print("三策略流程不停止任何节点，不等于真实节点故障或吞吐比较。")
    print("失败须保留原 phase/run，使用菜单10按原日志恢复；不能换名称掩盖失败。")
    name = label("新实验名称（最多48字符）：", maximum=48)
    folder = root / "client/file-cli-acceptance" / name / phase
    if folder.exists() or folder.is_symlink():
        raise ValueError(f"该阶段已存在，保留原操作并按其日志恢复：{folder}")
    print(f"操作日志、输入及读回目录：{folder}")
    print(f"最终报告：{folder / 'report/result.json'}")
    return [sys.executable, "-B", str(scripts / "file-cli-acceptance.py"),
            "--root", str(root), "--label", name, phase]


def usrbio_selection(root, scripts):
    file_api_profile(root)
    phase = choose("已挂载 mode4 的 USRBIO 功能验收", {
        "1": ("prepare", "prepare：新文件写入/同步后验证真实 USRBIO 读取"),
        "2": ("verify", "verify：正常重挂后，按原成功报告验证同一文件"),
    })
    print("须先确认原监督入口报告挂载成功；菜单不会挂载、卸载或重启服务。")
    if phase == "prepare":
        preparation = input_file("prepare-fuse-file 生成的 preparation.json 绝对路径：")
        file = new_path("本次新文件在已有挂载内的绝对路径：")
        print("固定合成数据配方：SHAKE256(3fs-mode4-usrbio-functional-v1)，长度20×shard_bytes+17。")
        print("shard_bytes沿用 preparation 配置；先经挂载写入/同步，再执行真实 USRBIO 读取。")
        prepared = None
    else:
        prepared = input_file("原成功 prepare 阶段的 result.json 绝对路径：")
        record = json_object(prepared)
        if (record.get("state") != "confirmed" or record.get("phase") != "prepare"
                or record.get("root") != str(root)
                or any(type(record.get(k)) is not str or not Path(record[k]).is_absolute()
                       for k in ("preparation", "file"))):
            raise ValueError("需要当前实验包原成功 prepare 的 result.json，不能使用失败或其它 root 的记录。")
        preparation, file = Path(record["preparation"]), Path(record["file"])
        print(f"固定原准备记录：{preparation}")
        print(f"固定原文件：{file}")
        print("verify 绑定原 prepare 的程序、配置、数据及状态；升级程序后不能冒充同一轮重挂。")
    output = new_path("本阶段新报告目录的绝对路径（已有本地父目录，挂载之外）：")
    print(f"最终报告：{output / 'result.json'}")
    print("配置、身份、实际挂载与完整性仍由正式脚本重新核验；本菜单不放宽任何检查。")
    command = [sys.executable, "-B", str(scripts / "mode4-usrbio-acceptance.py"), phase,
               "--root", str(root), "--preparation", str(preparation), "--helpers-dir", str(scripts),
               "--file", str(file), "--output-dir", str(output)]
    if prepared is not None:
        command += ["--prepared-record", str(prepared)]
    return command


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
    if (root / "cluster.json").exists():
        from native_v2_config import transport_settings
        transport = transport_settings(json.loads((root / "cluster.json").read_text(encoding="utf-8")))
        if transport is not None:
            print(f"既定数据传输：RDMA；网卡 {transport['interface']}；IPv4 {transport['ipv4']}；设备 {transport['ib_device']}。")
            print("本菜单沿用准备时的传输配置；配置声明不等于设备或数据路径已通过验收。")
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
    if target.name in {"file-cli-acceptance.py", "mode4-usrbio-acceptance.py"}:
        if input("确认上述配置、数据和命令；输入“执行”继续，其它输入取消：").strip() != "执行":
            print("已取消，未派发命令。")
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
    except (OSError, ValueError) as error:
        print(f"无法启动正式脚本：{error}", file=sys.stderr)
        raise SystemExit(2)
