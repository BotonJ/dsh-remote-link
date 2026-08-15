#!/bin/bash
# localtunnel 保活监督者：客户端任何 socket 错误都会 throw→进程死（bin/lt.js:80-82），
# 子域名已固定（my-subdomain），崩溃重启对用户完全透明。
LT=~/.npm/_npx/75ac80b86e83d4a2/node_modules/localtunnel/bin/lt.js
while true; do
  echo "[keepalive] $(date '+%H:%M:%S') starting localtunnel…"
  node "$LT" --port 3081 --subdomain my-subdomain
  echo "[keepalive] $(date '+%H:%M:%S') localtunnel exited (code=$?), restarting in 2s"
  sleep 2
done
