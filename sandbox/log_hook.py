"""Claude Code hook: append every hook event to /logs/agent.jsonl.

Claude Code runs this for UserPromptSubmit, PreToolUse and PostToolUse and
sends the event as JSON on stdin. A monitor must never break the agent, so
every error is swallowed and we always exit 0.
"""
import json
import os
import sys
from datetime import datetime, timezone

LOG = "/logs/agent.jsonl"
MAX = 2000  # longest string we keep from a tool's input


def short(value):
    """Cut very long strings (e.g. a whole file the agent writes)."""
    if isinstance(value, str) and len(value) > MAX:
        return value[:MAX] + f"...[cut, {len(value)} chars]"
    return value


def main():
    event = json.load(sys.stdin)
    tool_input = event.get("tool_input") or {}
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source": "agent",
        "run_id": os.environ.get("AGENTWATCH_RUN_ID") or event.get("session_id"),
        "session_id": event.get("session_id"),
        "hook": event.get("hook_event_name"),
        "tool": event.get("tool_name"),
        "tool_input": {k: short(v) for k, v in tool_input.items()},
        "prompt": event.get("prompt"),
        "cwd":event.get("cwd"),
    }
    if record["hook"] == "PostToolUse":
        # keep only the SIZE of the result, never its content:
        # if the agent read .env, the content IS the secret
        response = event.get("tool_response")
        record["response_chars"] = len(json.dumps(response)) if response is not None else 0
    with open(LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never block the agent because the monitor failed
        print(f"agentwatch hook error: {e}", file=sys.stderr)
    sys.exit(0)
