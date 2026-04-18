#!/bin/bash
# 启动隧道（如果还没开）
if ! lsof -i :2222 -sTCP:LISTEN -t &>/dev/null; then
  ssh -L 2222:172.20.20.2:22 orb -N &
  TUNNEL_PID=$!
  sleep 2
  echo "隧道已启动 (pid $TUNNEL_PID)"
fi

uv run python -m switch_audit.main --target localhost "$@"
