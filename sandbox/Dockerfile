
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-pytest git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

RUN groupadd -g 4242 agent \
 && useradd -u 4242 -g 4242 -d /home/agent -s /bin/bash agent

# AgentWatch: the hook script and the hooks config, owned by root, read-only for the agent
COPY log_hook.py /opt/agentwatch/log_hook.py
COPY claude-settings.json /etc/claude-code/managed-settings.json
RUN chmod 755 /opt/agentwatch/log_hook.py \
 && chmod 644 /etc/claude-code/managed-settings.json

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

WORKDIR /workspace
USER 4242:4242
CMD ["sleep", "infinity"]
