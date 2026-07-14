#!/usr/bin/env bash
# 本地交叉编译 Linux 二进制并把部署脚本一起收进 bin/。
# 在任意平台(含 Windows Git Bash)运行:
#
#   ./deploy/build.sh            # 默认 linux/amd64
#   GOARCH=arm64 ./deploy/build.sh
#
# 之后把 bin/ 里对应的「二进制 + 同名管理脚本」两个文件传到服务器即可:
#   scp bin/lightpn-hub   bin/lightpn-hub.sh   root@hub:/root/
#   scp bin/lightpn-agent bin/lightpn-agent.sh root@edge:/root/
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${GOARCH:=amd64}"
mkdir -p bin

echo "==> go build linux/$GOARCH"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o bin/lightpn-hub ./cmd/lightpn-hub
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o bin/lightpn-agent ./cmd/lightpn-agent

cp deploy/lightpn-hub.sh deploy/lightpn-agent.sh bin/

echo "==> 产物:"
ls -lh bin/
