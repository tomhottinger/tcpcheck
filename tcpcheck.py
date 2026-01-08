#!/usr/bin/env python3
"""
tcpcheck.py
Prüft, ob ein entfernter TCP-Port erreichbar ist.

Features:
- Host/Port Test via TCP connect
- Optionaler TLS-Handshake (SNI, Zertifikatsprüfung an/aus, CA-File)
- Optionaler "Probe"-Modus: nach Connect Bytes senden und Antwortmuster erwarten
- Retries, Timeout, parallele Checks, JSON/YAML-Konfig

Beispiele:
  python tcpcheck.py --host example.com --port 443 --tls
  python tcpcheck.py --config config.yaml
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    timeout_s: float = 3.0
    retries: int = 0
    retry_delay_s: float = 0.2

    mode: str = "connect"  # connect | tls | probe
    tls: Optional[Dict[str, Any]] = None
    probe: Optional[Dict[str, Any]] = None


@dataclass
class Result:
    ok: bool
    target: Target
    attempt: int
    elapsed_ms: int
    detail: str


def _now_ms() -> int:
    return int(time.time() * 1000)


def _compile_expect(expect: str, expect_is_regex: bool) -> Any:
    if expect_is_regex:
        return re.compile(expect.encode("utf-8"), re.DOTALL)
    return expect.encode("utf-8")


def _match_expect(data: bytes, expect_obj: Any, expect_is_regex: bool) -> bool:
    if expect_is_regex:
        return bool(expect_obj.search(data))
    return expect_obj in data


def check_target(t: Target) -> Result:
    last_err = ""
    for attempt in range(1, t.retries + 2):
        start = _now_ms()
        try:
            if t.mode == "connect":
                with socket.create_connection((t.host, t.port), timeout=t.timeout_s):
                    pass
                elapsed = _now_ms() - start
                return Result(True, t, attempt, elapsed, "tcp_connect_ok")

            if t.mode == "tls":
                tls_cfg = t.tls or {}
                server_name = tls_cfg.get("server_name") or t.host
                verify = bool(tls_cfg.get("verify", True))
                cafile = tls_cfg.get("cafile")
                capath = tls_cfg.get("capath")

                if verify:
                    ctx = ssl.create_default_context(cafile=cafile, capath=capath)
                else:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((t.host, t.port), timeout=t.timeout_s) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        _ = ssock.version()  # erzwingt Handshake
                elapsed = _now_ms() - start
                return Result(True, t, attempt, elapsed, "tls_handshake_ok")

            if t.mode == "probe":
                probe_cfg = t.probe or {}
                send_hex = probe_cfg.get("send_hex")
                send_text = probe_cfg.get("send_text")
                recv_bytes = int(probe_cfg.get("recv_bytes", 4096))
                read_timeout_s = float(probe_cfg.get("read_timeout_s", t.timeout_s))
                expect = probe_cfg.get("expect", "")
                expect_is_regex = bool(probe_cfg.get("expect_is_regex", False))

                if not (send_hex or send_text):
                    raise ValueError("probe requires send_hex or send_text")
                if not expect:
                    raise ValueError("probe requires expect")

                if send_hex:
                    payload = bytes.fromhex(str(send_hex).replace(" ", ""))
                else:
                    payload = str(send_text).encode("utf-8")

                expect_obj = _compile_expect(str(expect), expect_is_regex)

                with socket.create_connection((t.host, t.port), timeout=t.timeout_s) as sock:
                    sock.settimeout(read_timeout_s)
                    sock.sendall(payload)
                    data = sock.recv(recv_bytes)

                if not _match_expect(data, expect_obj, expect_is_regex):
                    raise RuntimeError(f"unexpected_response: {data[:200]!r}")

                elapsed = _now_ms() - start
                return Result(True, t, attempt, elapsed, "probe_ok")

            raise ValueError(f"unknown mode: {t.mode}")

        except Exception as e:
            elapsed = _now_ms() - start
            last_err = f"{type(e).__name__}: {e}"
            if attempt <= t.retries:
                time.sleep(t.retry_delay_s)
            else:
                return Result(False, t, attempt, elapsed, last_err)

    return Result(False, t, t.retries + 1, 0, last_err)


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML not installed. Install: pip install pyyaml")
        return yaml.safe_load(raw) or {}
    if ext == ".json":
        return json.loads(raw)
    raise ValueError("config must be .json or .yaml/.yml")


def targets_from_config(cfg: Dict[str, Any]) -> Tuple[List[Target], Dict[str, Any]]:
    defaults = cfg.get("defaults", {}) or {}
    out: List[Target] = []
    for item in (cfg.get("targets") or []):
        d = dict(defaults)
        d.update(item or {})

        name = str(d.get("name") or f"{d.get('host')}:{d.get('port')}")
        host = str(d["host"])
        port = int(d["port"])

        out.append(
            Target(
                name=name,
                host=host,
                port=port,
                timeout_s=float(d.get("timeout_s", 3.0)),
                retries=int(d.get("retries", 0)),
                retry_delay_s=float(d.get("retry_delay_s", 0.2)),
                mode=str(d.get("mode", "connect")),
                tls=d.get("tls"),
                probe=d.get("probe"),
            )
        )
    opts = cfg.get("options", {}) or {}
    return out, opts


def print_result(r: Result, fmt: str) -> None:
    if fmt == "text":
        status = "OK" if r.ok else "FAIL"
        print(f"{status}\t{r.target.name}\t{r.target.host}:{r.target.port}\t{r.elapsed_ms}ms\t{r.detail}")
        return

    obj = {
        "ok": r.ok,
        "name": r.target.name,
        "host": r.target.host,
        "port": r.target.port,
        "mode": r.target.mode,
        "attempt": r.attempt,
        "elapsed_ms": r.elapsed_ms,
        "detail": r.detail,
    }
    print(json.dumps(obj, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--config", help="Pfad zu .yaml/.yml oder .json")
    ap.add_argument("--host", help="Host (ohne config)")
    ap.add_argument("--port", type=int, help="Port (ohne config)")
    ap.add_argument("--timeout", type=float, default=3.0, help="Timeout Sekunden (ohne config)")
    ap.add_argument("--retries", type=int, default=0, help="Retries (ohne config)")
    ap.add_argument("--retry-delay", type=float, default=0.2, help="Delay zwischen Retries (ohne config)")
    ap.add_argument("--mode", choices=["connect", "tls", "probe"], default="connect", help="Testmodus (ohne config)")
    ap.add_argument("--tls", action="store_true", help="Alias für --mode tls")
    ap.add_argument("--server-name", help="TLS SNI/hostname (ohne config)")
    ap.add_argument("--no-verify", action="store_true", help="TLS Zertifikatsprüfung deaktivieren (ohne config)")
    ap.add_argument("--cafile", help="CA File (ohne config)")
    ap.add_argument("--capath", help="CA Path (ohne config)")
    ap.add_argument("--send-text", help="Probe: Text senden (UTF-8)")
    ap.add_argument("--send-hex", help="Probe: Hex senden, z.B. '16 03 01 ...'")
    ap.add_argument("--expect", help="Probe: erwarteter Substring oder Regex")
    ap.add_argument("--expect-regex", action="store_true", help="Probe: expect als Regex interpretieren")
    ap.add_argument("--recv-bytes", type=int, default=4096, help="Probe: max Bytes lesen")
    ap.add_argument("--read-timeout", type=float, help="Probe: Lese-Timeout Sekunden")
    ap.add_argument("--parallel", type=int, default=8, help="Parallelität bei config targets")
    ap.add_argument("--format", choices=["text", "jsonl"], default="text", help="Ausgabeformat")
    args = ap.parse_args()

    fmt = "text" if args.format == "text" else "jsonl"

    targets: List[Target] = []
    parallel = int(args.parallel)

    if args.config:
        cfg = load_config(args.config)
        targets, opts = targets_from_config(cfg)
        parallel = int(opts.get("parallel", parallel))
        fmt = str(opts.get("format", "text"))
        if fmt not in ("text", "jsonl"):
            fmt = "text"
    else:
        if not (args.host and args.port):
            raise SystemExit("Either --config or (--host and --port) required")

        mode = "tls" if args.tls else args.mode

        tls_cfg = None
        probe_cfg = None

        if mode == "tls":
            tls_cfg = {
                "server_name": args.server_name,
                "verify": not args.no_verify,
                "cafile": args.cafile,
                "capath": args.capath,
            }

        if mode == "probe":
            probe_cfg = {
                "send_text": args.send_text,
                "send_hex": args.send_hex,
                "expect": args.expect,
                "expect_is_regex": bool(args.expect_regex),
                "recv_bytes": int(args.recv_bytes),
                "read_timeout_s": float(args.read_timeout) if args.read_timeout is not None else None,
            }
            if probe_cfg["read_timeout_s"] is None:
                probe_cfg.pop("read_timeout_s")

        targets = [
            Target(
                name=f"{args.host}:{args.port}",
                host=args.host,
                port=int(args.port),
                timeout_s=float(args.timeout),
                retries=int(args.retries),
                retry_delay_s=float(args.retry_delay),
                mode=mode,
                tls=tls_cfg,
                probe=probe_cfg,
            )
        ]

    if not targets:
        raise SystemExit("No targets in config")

    ok_all = True
    with cf.ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = [ex.submit(check_target, t) for t in targets]
        for fut in cf.as_completed(futs):
            r = fut.result()
            if not r.ok:
                ok_all = False
            print_result(r, fmt)

    return 0 if ok_all else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
