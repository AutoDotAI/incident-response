"""CLI for an operator-provided adapter; no adapter or credentials ship here."""

from __future__ import annotations

import argparse
import importlib
import json
import time
from collections.abc import Callable
from typing import Any

from .policy import Responder, ResponderAdapter


def load_adapter(reference: str) -> ResponderAdapter:
    """Load a trusted local integration factory named `module:factory`."""
    module_name, separator, factory_name = reference.partition(":")
    if not separator or not module_name or not factory_name or not factory_name.isidentifier():
        raise ValueError("--adapter must be a trusted module:factory reference")
    factory = getattr(importlib.import_module(module_name), factory_name)
    if not callable(factory):
        raise ValueError("--adapter factory is not callable")
    return factory()


def run(argv: list[str] | None = None, *, adapter: ResponderAdapter | None = None,
        sleep: Callable[[float], Any] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description="Bounded local incident responder")
    parser.add_argument("--adapter", help="trusted integration module:factory; optional when injected")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("once", help="respond to persisted open alerts once")
    commands.add_parser("serve", help="poll persisted open alerts every five seconds")
    inspect = commands.add_parser("inspect", help="respond to one owned alert")
    inspect.add_argument("alert_id")
    inspect.add_argument("owner_id")
    args = parser.parse_args(argv)
    if adapter is None:
        if not args.adapter:
            parser.error("--adapter is required unless an adapter is injected")
        try:
            adapter = load_adapter(args.adapter)
        except (ImportError, AttributeError, ValueError) as error:
            parser.error(str(error))
    responder = Responder(adapter)
    try:
        if args.command == "inspect":
            print(json.dumps(responder.respond(args.alert_id, args.owner_id)
                             or {"status": "no_open_owned_alert"}, separators=(",", ":")))
        elif args.command == "once":
            print(json.dumps(responder.run_open_once(), separators=(",", ":")))
        else:
            while True:
                responder.run_open_once()
                sleep(5)
    except KeyboardInterrupt:
        return 0
    finally:
        close = getattr(adapter, "close", None)
        if callable(close):
            close()
    return 0


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
