#!/bin/bash
# dsh.example.dev 专用 named tunnel（本地管理）。协议参数必须在命令行强制：
# 本网络 IPv6 边缘拨号超时、config 文件里的 protocol 会被 run 子命令忽略。
while true; do
  echo "[cf-tunnel] $(date '+%H:%M:%S') starting…"
  cloudflared tunnel --protocol http2 --edge-ip-version 4 --config ~/.cloudflared/config-dsh.yml run
  echo "[cf-tunnel] $(date '+%H:%M:%S') exited (code=$?), retry in 3s"
  sleep 3
done
