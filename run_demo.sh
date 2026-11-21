#!/usr/bin/env bash
# AgentWatch live demo: a clean run vs. a prompt-injected run.
# Usage: ./run_demo.sh        -> s0 + s1
#        ./run_demo.sh all    -> s0 + s1 + s2 + s3
set -euo pipefail
cd "$(dirname "$0")"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1. Pre-flight: sandbox, proxy, auditd"
sudo -v
docker start agent-sandbox proxy > /dev/null
docker ps --format '   {{.Names}}: {{.Status}}' --filter name=agent-sandbox --filter name=proxy
if ! sudo auditctl -l | grep -q 'key=aw_'; then
  sudo auditctl -R audit/agentwatch.rules > /dev/null
fi
echo "   auditd rules loaded: $(sudo auditctl -l | grep -c 'key=aw_')"

step "2. Fresh evidence"
: > logs/agent/agent.jsonl
: > logs/runs.jsonl
: > logs/proxy/proxy.log
docker restart proxy > /dev/null
sleep 2

step "3. Replay scenarios"
scenarios=(s0_benign s1_prompt_injection)
if [[ "${1:-}" == "all" ]]; then
  scenarios+=(s2_test_tampering s3_typosquat)
fi
for s in "${scenarios[@]}"; do
  python3 scenarios/run_scenario.py "scenarios/$s.json"
  sleep 3
done

step "4. Export kernel evidence"
sudo cat /var/log/audit/audit.log | python3 audit/export_audit.py > logs/audit/audit.jsonl

step "5. Correlate"
python3 correlator/correlator.py

step "6. Dashboard: http://127.0.0.1:8501   (Ctrl+C to stop)"
exec .venv/bin/streamlit run dashboard/app.py \
  --server.address 127.0.0.1 --browser.gatherUsageStats false
