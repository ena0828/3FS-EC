#!/usr/bin/env python3
"""易读的 EC 文件命令入口；打印等价命令后以 exec 交给原生客户端。"""
import argparse
import json
import os
from pathlib import Path
import shlex
import sys


RIGHTS = {"read": 1, "write": 2, "read-write": 3}


def decimal(value):
    if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value.startswith("0")):
        raise argparse.ArgumentTypeError("使用无前导零的非负十进制整数")
    if len(value) > 20 or int(value) > 2**64 - 1:
        raise argparse.ArgumentTypeError("数值超过 uint64 范围")
    return value


def shards(value, sizes):
    items = tuple(int(decimal(part)) for part in value.split(","))
    if len(items) not in sizes or len(set(items)) != len(items) or any(item > 11 for item in items):
        raise argparse.ArgumentTypeError("分片索引须为0至11、互不重复，目标1或2片，源恰好10片")
    return items


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True, help="已配置 --file-api 的实验目录")
    p.add_argument("--show-command", action="store_true", help="仅显示命令，不运行实验")
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("create", "open", "resume-open", "pwrite", "resume", "query", "seal", "close",
                 "read", "resume-read", "release-read", "truncate", "resume-truncate", "query-truncate",
                 "close-truncate-debt", "append", "resume-append", "query-append", "seal-append",
                 "fsync", "resume-fsync", "repair", "resume-repair", "query-repair", "close-repair-debt"):
        item = sub.add_parser(name)
        item.add_argument("--run-dir", type=Path, required=True, help="该操作的固定日志目录；新操作必须使用新目录")
        if name in ("repair", "resume-repair", "query-repair", "close-repair-debt"):
            item.add_argument("--metrics", action=argparse.BooleanOptionalAction, default=None,
                              help="显式开启/关闭本次原生修复计量；默认沿用配置（默认关闭），开启有计量开销")
        if name in ("pwrite", "read", "truncate", "append", "fsync", "repair"):
            item.add_argument("--session", type=Path, required=True, help="已接受会话的原日志目录")
        if name in ("pwrite", "read"):
            item.add_argument("--offset", type=decimal, required=True, help="字节偏移")
        if name in ("pwrite", "append"):
            item.add_argument("--input", type=Path, required=True)
        if name in ("read", "resume-read"):
            item.add_argument("--output", type=Path, required=True, help="新的独占输出文件")
        if name == "read":
            item.add_argument("--length", type=decimal, required=True, help="最大读取字节数，实际受 EOF 限制")
        if name == "repair":
            item.add_argument("--stripe", type=decimal, required=True, help="文件中的条带索引")
            item.add_argument("--targets", type=lambda value: shards(value, (1, 2)), required=True,
                              help="待重建的1或2个分片索引，以英文逗号分隔，例如0,11")
            item.add_argument("--sources", type=lambda value: shards(value, (10,)), required=True,
                              help="固定的10个源分片索引与顺序，不得包含待重建片")
            item.add_argument("--strategy", choices=("central", "pipeline", "helper"), required=True)
            item.add_argument("--window", choices=("1", "2", "3", "4"), default="2")
        if name == "truncate":
            item.add_argument("--length", type=decimal, required=True, help="新文件长度，单位为字节")
        if name in ("create", "open"):
            item.add_argument("--rights", choices=RIGHTS, default="read-write")
        if name == "create":
            item.add_argument("--path", required=True, help="3FS 中的绝对文件路径")
            item.add_argument("--shard-bytes", type=decimal, default="1048576")
            item.add_argument("--permission", type=decimal, default="384", help="权限的十进制值，384 对应 0600")
        if name == "open":
            item.add_argument("--inode", type=decimal, required=True)
            item.add_argument("--incarnation", required=True)
            item.add_argument("--birth", required=True)
    return p


def absolute(path):
    if not path.is_absolute() or path != path.resolve():
        raise ValueError(f"要求无符号链接的绝对路径：{path}")
    return str(path)


def command(args):
    root = Path(absolute(args.root))
    manifest = json.loads((root / "cluster.json").read_text(encoding="utf-8"))
    if manifest.get("file_api") is not True or manifest.get("root") != str(root):
        raise ValueError("此目录未明确配置文件 API；请使用新目录 prepare --profile gc --file-api")
    options = {"run_dir": absolute(args.run_dir)}
    mapping = {"session": "session_run_dir", "offset": "offset_decimal", "input": "input_file",
               "output": "output_file", "length": "length_decimal", "path": "file_path",
               "shard_bytes": "shard_bytes", "permission": "permission", "inode": "inode_decimal",
               "incarnation": "incarnation", "birth": "birth"}
    for source, target in mapping.items():
        if hasattr(args, source):
            value = getattr(args, source)
            options[target] = absolute(value) if isinstance(value, Path) else value
    if args.action == "repair":
        if set(args.targets) & set(args.sources):
            raise ValueError("固定源集合不得包含待重建片")
        options.update(repair_stripe_decimal=args.stripe,
                       repair_mask_decimal=str(sum(1 << item for item in args.targets)),
                       repair_source_order=",".join(str(item) for item in args.sources),
                       repair_mode=args.strategy, repair_window_decimal=args.window)
    if hasattr(args, "rights"):
        options["session_rights"] = RIGHTS[args.rights]
    if getattr(args, "metrics", None) is not None:
        options["repair_metrics"] = "true" if args.metrics else "false"
    if args.action == "create" and not args.path.startswith("/"):
        raise ValueError("--path 必须为 3FS 绝对路径")
    return [str(root / "bin/ec_file_cli"), f"--cfg={root / 'client/file-client.toml'}",
            *[f"--config.{key}={value}" for key, value in options.items()], "mode4-" + args.action]


def main():
    args = parser().parse_args()
    argv = command(args)
    environment = os.environ.copy()
    environment.pop("LD_PRELOAD", None)
    environment["LD_LIBRARY_PATH"] = str(args.root / "lib")
    print("等价命令：", flush=True)
    print("env -u LD_PRELOAD " + shlex.quote("LD_LIBRARY_PATH=" + environment["LD_LIBRARY_PATH"]) +
          " " + shlex.join(argv), flush=True)
    if args.show_command:
        return 0
    if sys.platform != "linux":
        raise ValueError("实际运行须在 Linux/WSL 中进行")
    # No timer, sampling thread, retry or identity generation survives exec.
    # The native journal owns operation and recovery semantics.
    os.execve(argv[0], argv, environment)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"未启动原生操作：{error}", file=sys.stderr)
        sys.exit(2)
