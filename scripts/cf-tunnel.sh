#!/bin/bash
# dsh.example.dev 专用 named tunnel（本地管理）。协议参数必须在命令行强制：
# 本网络 IPv6 边缘拨号超时、config 文件里的 protocol 会被 run 子命令忽略。
#
# 心跳：连接器存活期间每 30s 向 $TUNNEL_HEARTBEAT 写入 epoch 秒，
# dsh-remote-link 的 /status 页读取该文件展示隧道连接器存活时长。
HEARTBEAT="${TUNNEL_HEARTBEAT:-$HOME/.cloudflared/dsh-tunnel.beat}"
while true; do
  echo "[cf-tunnel] $(date '+%H:%M:%S') starting…"
  cloudflared tunnel --protocol http2 --edge-ip-version 4 --config ~/.cloudflared/config-dsh.yml run &
  CFPID=$!
  (
    while kill -0 "$CFPID" 2>/dev/null; do
      date +%s > "$HEARTBEAT"
      sleep 30
    done
  ) &
  HBPID=$!
  wait "$CFPID"
  echo "[cf-tunnel] $(date '+%H:%M:%S') exited (code=$?), retry in 3s"
  kill "$HBPID" 2>/dev/null
  sleep 3
done
