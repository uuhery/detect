#!/bin/bash
set -e

SW_A_IP="172.20.20.2"
SW_B_IP="172.20.20.3"
TOPO="/Users/uu/Projects/detect/topo.yaml"

# 确保容器在跑，不在就部署
if ! ssh orb "docker inspect clab-detect-audit-lab-sw-a --format '{{.State.Running}}' 2>/dev/null" | grep -q "^true$"; then
  echo "靶场未运行，正在部署..."
  ssh orb "clab destroy -t $TOPO --cleanup 2>/dev/null; clab deploy -t $TOPO 2>&1"
fi

# 杀掉旧隧道，重建干净的（幂等，每次都重建避免僵尸隧道）
lsof -i :2222 -sTCP:LISTEN -t 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -i :8080 -sTCP:LISTEN -t 2>/dev/null | xargs kill -9 2>/dev/null || true
ssh -L 2222:${SW_A_IP}:22 orb -N &
ssh -L 8080:${SW_A_IP}:80 orb -N &

# 等 SSH 端口就绪（最多 90 秒）
echo -n "等待 sw-a SSH 就绪"
for i in $(seq 1 30); do
  if nc -z localhost 2222 2>/dev/null; then
    echo " 就绪"
    break
  fi
  echo -n "."
  sleep 3
  if [ $i -eq 30 ]; then
    echo " 超时，请检查靶场"
    exit 1
  fi
done

echo "拓扑: Mac→sw-a(${SW_A_IP}) sw-b(${SW_B_IP})[仅 pivot 可达]"

if [ $# -eq 0 ]; then
  uv run python -m switch_audit.main --target localhost
else
  uv run python -m switch_audit.main "$@"
fi
