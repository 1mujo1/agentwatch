#!/usr/bin/env python3
"""Replay one AgentWatch scenario inside the sandbox.

Usage: python3 scenarios/run_scenario.py scenarios/s1_prompt_injection.json
"""
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "workspace"
BASELINE = ROOT / "scenarios" / "baseline"
RUNS = ROOT / "logs" / "runs.jsonl"
CONTAINER = "agent-sandbox"
HOOK = "/opt/agentwatch/log_hook.py"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def reset_workspace(setup_files):
    """Put workspace/ back to the clean baseline, then plant the scenario's files."""
    for item in WORKSPACE.iterdir():            # empty the folder, but keep the folder itself
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    shutil.copytree(BASELINE, WORKSPACE, dirs_exist_ok=True)
    for name, content in setup_files.items():
        (WORKSPACE / name).write_text(content)


def hook(run_id, event):
    """Send one event through the REAL hook script, exactly like Claude Code does."""
    event = {"session_id": run_id, "cwd": "/workspace", **event}
    subprocess.run(
        ["docker", "exec", "-i", "-e", f"AGENTWATCH_RUN_ID={run_id}",
         CONTAINER, "python3", HOOK],
        input=json.dumps(event), text=True, check=True)


def in_sandbox(command):
    """Run a shell command inside the sandbox as uid 4242. Returns (exit code, output)."""
    p = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", command],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    scenario = json.loads(Path(sys.argv[1]).read_text())
    run_id = f"{scenario['name']}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    reset_workspace(scenario.get("setup_files", {}))
    start = now()
    print(f"== {run_id}: {scenario['task']}")

    hook(run_id, {"hook_event_name": "UserPromptSubmit", "prompt": scenario["task"]})
    for i, step in enumerate(scenario["steps"], 1):
        base = {"tool_name": step["tool"], "tool_input": step["input"]}
        hook(run_id, {"hook_event_name": "PreToolUse", **base})
        code, out = in_sandbox(step["run"])
        hook(run_id, {"hook_event_name": "PostToolUse", **base,
                      "tool_response": {"exit_code": code, "output": out}})
        last = out.splitlines()[-1][:70] if out else ""
        print(f"  [{i}] {step['tool']:<5} exit={code}  {last}")
        time.sleep(1)

    time.sleep(2)  # give auditd and the proxy time to finish writing
    record = {"run_id": run_id, "scenario": scenario["name"], "task": scenario["task"],
              "expected": scenario["expected"], "mode": "replay",
              "start": start, "end": now()}
    with RUNS.open("a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"== done. Window {record['start']} -> {record['end']}")


if __name__ == "__main__":
    main()
