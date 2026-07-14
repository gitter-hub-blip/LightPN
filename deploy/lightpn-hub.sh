#!/usr/bin/env bash
# LightPN hub 服务器端管理脚本(systemd Linux)。
# 与 lightpn-hub 二进制放在同一目录,以 root 运行:
#
#   sudo ./lightpn-hub.sh install --public-addr 203.0.113.10:7440
#   sudo ./lightpn-hub.sh status
#   sudo ./lightpn-hub.sh uninstall
#
# 所有文件(二进制/配置/数据)集中安装在用户主目录下的 ~/lightpn,
# 只有 systemd 单元放在 /etc/systemd/system。系统里装了什么一目了然,
# 卸载时删掉单元 + 整个目录即净。
# systemd 单元内嵌在本脚本里,服务器上只需要「二进制 + 本脚本」两个文件。
set -euo pipefail

SERVICE=lightpn-hub
UNIT=/etc/systemd/system/lightpn-hub.service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 安装目录默认 <运行 sudo 的用户主目录>/lightpn;可用 LIGHTPN_DIR 环境变量
# 或 install --dir 覆盖。已安装过时,一律以 unit 里记录的实际路径为准,
# 避免换个用户执行脚本时算出不同目录。
default_app_dir() {
  local home="$HOME"
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  fi
  echo "$home/lightpn"
}
detect_app_dir() {
  if [ -f "$UNIT" ]; then
    local exec_bin
    exec_bin="$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$UNIT")"
    if [ -n "$exec_bin" ]; then dirname "$exec_bin"; return; fi
  fi
  echo "${LIGHTPN_DIR:-$(default_app_dir)}"
}

set_paths() {
  APP_DIR="$1"
  BIN_DST="$APP_DIR/lightpn-hub"
  DATA_DIR="$APP_DIR/hub-data"
  CONF="$APP_DIR/hub.json"
}
set_paths "$(detect_app_dir)"

usage() {
  cat <<EOF
用法: lightpn-hub.sh <命令> [选项]

  install [--public-addr <ip:port>] [--dir <安装目录>] [--bin <路径>]
                安装到 $APP_DIR(二进制/配置/数据都在里面),写 systemd
                单元,首次安装引导设置管理员密码,然后启动并设为开机自启。
                可重复执行(升级二进制/改公网地址时重跑即可)。
  password      重设管理员密码
  start / stop / restart / status
  logs [-f]     查看日志(-f 持续跟踪)
  uninstall [--keep-data] [--yes]
                停止并移除服务与整个 $APP_DIR。数据(SQLite + CA)一并删除
                意味着销毁 CA、所有 agent 证书作废,不可逆,需输入 yes 确认;
                --keep-data 只删二进制与单元,保留数据目录。

提示: hub 下线不影响已建立的隧道;备份只需 $DATA_DIR。
EOF
}

die() { echo "lightpn-hub.sh: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "需要 root 权限,请用 sudo 运行"; }

write_unit() {
  cat >"$UNIT" <<EOF
[Unit]
Description=LightPN hub (control plane + admin panel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DST --data-dir $DATA_DIR --config $CONF
Restart=always
RestartSec=3

# Hardening. Runs as root; ProtectSystem=strict keeps the filesystem
# read-only except the app dir under the user's home (hence no
# ProtectHome, which would mask /home and /root entirely).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
}

cmd_install() {
  need_root
  local bin_src="$SCRIPT_DIR/lightpn-hub" public_addr=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --public-addr) public_addr="${2:?--public-addr 需要参数}"; shift 2 ;;
      --dir)         set_paths "${2:?--dir 需要参数}"; shift 2 ;;
      --bin)         bin_src="${2:?--bin 需要参数}"; shift 2 ;;
      *) die "未知选项: $1" ;;
    esac
  done
  [ -f "$bin_src" ] || die "找不到二进制 $bin_src(把 lightpn-hub 与本脚本放同一目录,或用 --bin 指定)"

  echo "==> 安装到 $APP_DIR"
  mkdir -p "$APP_DIR"
  # 先停服务再覆盖,避免 "text file busy";源与目标是同一文件则跳过
  systemctl stop "$SERVICE" 2>/dev/null || true
  if ! [ "$bin_src" -ef "$BIN_DST" ]; then
    install -m 755 "$bin_src" "$BIN_DST"
  fi

  if [ -z "$public_addr" ] && [ ! -f "$CONF" ]; then
    echo "public_addr 是 agent 入网后回连 hub 的地址,强烈建议显式配置。"
    read -rp "hub 公网地址 (ip:port,如 203.0.113.10:7440,回车跳过): " public_addr
  fi
  if [ -n "$public_addr" ]; then
    printf '{ "public_addr": "%s" }\n' "$public_addr" >"$CONF"
    echo "==> 已写入 $CONF"
  fi

  echo "==> 安装 systemd 单元 $UNIT"
  write_unit
  systemctl daemon-reload

  if [ ! -f "$DATA_DIR/hub.db" ]; then
    echo "==> 首次安装,设置管理员密码(至少 8 位)"
    "$BIN_DST" admin set-password --data-dir "$DATA_DIR"
  fi

  echo "==> 启动服务"
  systemctl enable --now "$SERVICE"
  systemctl --no-pager --lines 0 status "$SERVICE" || true

  cat <<EOF

安装完成。接下来:
  1. 防火墙放行 7440/tcp(控制通道);不要放行 7441(面板只绑 127.0.0.1)。
  2. 面板经隧道/反代访问 http://127.0.0.1:7441(推荐 Cloudflare Tunnel + Access)。
  3. 在面板生成一次性 token,到边缘机器上执行:
       sudo ./lightpn-agent.sh install --hub <本机公网IP>:7440 --token lp_xxxx
EOF
}

cmd_uninstall() {
  need_root
  local keep_data=0 yes=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --keep-data) keep_data=1; shift ;;
      --yes)       yes=1; shift ;;
      *) die "未知选项: $1" ;;
    esac
  done

  echo "==> 停止并移除服务"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload

  if [ "$keep_data" = 1 ]; then
    rm -f "$BIN_DST"
    echo "已保留数据 $DATA_DIR 与配置 $CONF(重装后可继续使用)。"
  else
    echo "即将删除整个 $APP_DIR(含 SQLite + CA 密钥)。"
    echo "CA 销毁后所有 agent 证书作废、无法再撮合,此操作不可逆!"
    if [ "$yes" != 1 ]; then
      read -rp "确认删除请输入 yes: " ans
      [ "$ans" = yes ] || { echo "已跳过数据删除(服务与单元已移除)。"; exit 0; }
    fi
    rm -rf "$APP_DIR"
    echo "已删除 $APP_DIR。"
  fi
  echo "卸载完成。别忘了逐台清理边缘节点: sudo ./lightpn-agent.sh uninstall"
}

case "${1:-}" in
  install)   shift; cmd_install "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  password)  need_root; "$BIN_DST" admin set-password --data-dir "$DATA_DIR" ;;
  start)     need_root; systemctl start "$SERVICE"; echo "已启动" ;;
  stop)      need_root; systemctl stop "$SERVICE"; echo "已停止" ;;
  restart)   need_root; systemctl restart "$SERVICE"; echo "已重启" ;;
  status)    systemctl --no-pager status "$SERVICE" || true ;;
  logs)      shift; journalctl -u "$SERVICE" -n 100 "$@" ;;
  -h|--help|help|"") usage ;;
  *) usage; die "未知命令: $1" ;;
esac
