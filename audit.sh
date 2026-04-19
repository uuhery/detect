#!/bin/bash
set -e

SWITCH_IP="172.20.20.2"
TOPO="/Users/uu/Projects/detect/topo.yaml"

# 确保 clab 靶场在 orb 里运行
if ! ssh orb "docker inspect clab-detect-audit-lab-sw-target --format '{{.State.Running}}' 2>/dev/null" | grep -q "^true$"; then
  echo "sw-target 未运行，正在部署靶场..."
  ssh orb "clab deploy -t $TOPO --reconfigure 2>&1"
  echo "靶场已就绪"
fi

# 启动 SSH 隧道（如果还没开）
if ! lsof -i :2222 -sTCP:LISTEN -t &>/dev/null; then
  ssh -L 2222:${SWITCH_IP}:22 orb -N &
  sleep 2
  echo "隧道已启动 -> orb:${SWITCH_IP}:22 (SSH)"
fi

# 启动 eAPI HTTP 隧道（NAPALM EOS driver 用）
if ! lsof -i :8080 -sTCP:LISTEN -t &>/dev/null; then
  ssh -L 8080:${SWITCH_IP}:80 orb -N &
  sleep 2
  echo "隧道已启动 -> orb:${SWITCH_IP}:80 (eAPI HTTP)"
fi

uv run python -m switch_audit.main --target localhost "$@"
