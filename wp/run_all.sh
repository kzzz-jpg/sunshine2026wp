#!/usr/bin/env bash
# 一鍵重跑全部 7 題的 exploit（打遠端），確認每一題都還能拿到 flag。
#
#   ./run_all.sh            # 跑全部
#   ./run_all.sh pwn3       # 只跑某一題
#
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(pwn1 pwn2 pwn3 pwn4 pwn5 pwn6 pwn7)

declare -A PORTS=(
  [pwn1]=26003 [pwn2]=26001 [pwn3]=26002 [pwn4]=26004
  [pwn5]=26008 [pwn6]=26005 [pwn7]=26007
)

for t in "${TARGETS[@]}"; do
  echo "=============================================================="
  echo ">>> $t  (port ${PORTS[$t]})"
  echo "=============================================================="
  if [ ! -f "$ROOT/$t/exploit.py" ]; then
    echo "!! 找不到 $t/exploit.py"
    continue
  fi
  ( cd "$ROOT/$t" && timeout 300 python3 exploit.py REMOTE PORT="${PORTS[$t]}" < /dev/null 2>&1 | tr -d '\000' | tail -n 30 )
  echo
done
