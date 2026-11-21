#!/usr/bin/env python3
"""Turn raw auditd lines (stdin) into one JSON object per agent event (stdout).

Usage:
  sudo cat /var/log/audit/audit.log | python3 audit/export_audit.py > logs/audit/audit.jsonl
"""
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone

# "type=SYSCALL msg=audit(1731000000.123:456):" -> record type, epoch time, serial
HEADER = re.compile(r"type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):")
# key=value pairs: the value is "quoted" or a run of non-space characters
FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
# fields that auditd writes as hex when they contain unusual characters
HEX_FIELDS = {"comm", "exe", "cwd", "name", "proctitle"}
ARG = re.compile(r"a\d+")


def decode(field, value, rtype):
    """Return the readable value of one field."""
    if value.startswith('"'):                      # quoted = already plain text
        return value[1:-1]
    if field in HEX_FIELDS or (rtype == "EXECVE" and ARG.fullmatch(field)):
        try:                                       # unquoted = hex-encoded text
            raw = bytes.fromhex(value)
            return raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except ValueError:                         # e.g. name=(null)
            return value
    return value


def sockaddr(hexstr):
    """Unpack the kernel's binary socket address into family / ip / port."""
    b = bytes.fromhex(hexstr)
    family = int.from_bytes(b[0:2], "little")
    if family == 2 and len(b) >= 8:                # AF_INET (IPv4)
        return {"family": "inet", "ip": str(ipaddress.IPv4Address(b[4:8])),
                "port": int.from_bytes(b[2:4], "big")}
    if family == 10 and len(b) >= 24:              # AF_INET6 (IPv6)
        return {"family": "inet6", "ip": str(ipaddress.IPv6Address(b[8:24])),
                "port": int.from_bytes(b[2:4], "big")}
    if family == 1:                                # AF_UNIX (local socket)
        return {"family": "unix", "path": b[2:].split(b"\0")[0].decode("utf-8", "replace")}
    return {"family": str(family)}


def build(event_id, epoch, records):
    """Merge all records of one event into a single JSON-ready dict."""
    sc, args, paths, cwd, dest, title = {}, [], [], "", None, ""
    for rtype, f in records:
        if rtype == "SYSCALL":
            sc = f
        elif rtype == "EXECVE":
            keys = sorted((k for k in f if ARG.fullmatch(k)), key=lambda k: int(k[1:]))
            args = [f[k] for k in keys]
        elif rtype == "CWD":
            cwd = f.get("cwd", "")
        elif rtype == "PATH" and f.get("nametype") != "PARENT":
            paths.append(f.get("name", ""))
        elif rtype == "SOCKADDR" and "saddr" in f:
            dest = sockaddr(f["saddr"])
        elif rtype == "PROCTITLE":
            title = f.get("proctitle", "")

    key = sc.get("key", "")
    if not key.startswith("aw_"):                  # keep only our AgentWatch rules
        return None

    # relative paths ("tests/x.py") become absolute using the process's folder
    paths = [p if p.startswith("/") or not cwd else os.path.normpath(os.path.join(cwd, p))
             for p in paths]

    return {
        "ts": datetime.fromtimestamp(epoch, timezone.utc)
              .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "epoch": epoch,
        "source": "audit",
        "event_id": event_id,
        "key": key,
        "syscall": sc.get("syscall"),
        "success": sc.get("success") == "yes",
        "exit": sc.get("exit"),
        "uid": int(sc.get("uid", -1)),
        "pid": int(sc.get("pid", -1)),
        "ppid": int(sc.get("ppid", -1)),
        "comm": sc.get("comm"),
        "exe": sc.get("exe"),
        "cwd": cwd,
        "cmdline": " ".join(args) if args else title,
        "paths": paths,
        "dest": dest,
    }


def main():
    events = {}                                    # event_id -> (epoch, [records])
    for line in sys.stdin:
        line = line.split("\x1d")[0]               # drop auditd's "enriched" suffix
        m = HEADER.match(line)
        if not m:
            continue
        rtype, epoch, serial = m.group(1), float(m.group(2)), m.group(3)
        fields = {k: decode(k, v, rtype) for k, v in FIELD.findall(line[m.end():])}
        event_id = f"{m.group(2)}:{serial}"
        events.setdefault(event_id, (epoch, []))[1].append((rtype, fields))

    out = [build(eid, ep, recs) for eid, (ep, recs) in events.items()]
    for ev in sorted((e for e in out if e), key=lambda e: e["epoch"]):
        print(json.dumps(ev))


if __name__ == "__main__":
    main()
