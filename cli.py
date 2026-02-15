from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from blocks import BLOCKS
from utils import parse_extras


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="community-cli",
        description="Block CLI for the P2P community app.",
    )
    available = ", ".join(BLOCKS.names()) or "(none)"
    p.add_argument("block", help=f"Block to run. Available: {available}")
    p.add_argument("prompt", nargs="?", default=None, help="Input payload (or stdin if omitted)")
    p.add_argument("--extra", action="append", default=[], help="group.key=val or key=val")
    p.add_argument("--json", action="store_true", help="Print JSON result+metadata")
    return p


def read_prompt(arg: Optional[str]) -> str:
    if arg is not None:
        return arg
    if sys.stdin.isatty():
        print("Enter payload then Ctrl+D:", file=sys.stderr)
    return sys.stdin.read()


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    extras = parse_extras(args.extra)
    payload = read_prompt(args.prompt)

    try:
        blk = BLOCKS.create(args.block)
        params: Dict[str, Any] = {}
        params.update(extras.get("all", {}))
        params.update(extras.get(args.block.lower(), {}))

        result, meta = blk.execute(payload, params=params)

        if args.json:
            print(json.dumps({"block": args.block, "metadata": meta, "result": result}, indent=2, ensure_ascii=False))
        else:
            if isinstance(result, (dict, list)):
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(str(result))
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
