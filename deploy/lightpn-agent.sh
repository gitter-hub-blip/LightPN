#!/usr/bin/env bash
# LightPN agent 边缘节点管理脚本(systemd Linux,内核 ≥ 5.6 内建 WireGuard)。
# 与 lightpn-agent 二进制放在同一目录,以 root 运行:
#
#   sudo ./lightpn-agent.sh install --hub 203.0.113.10:7440 --token lp_xxxx
#   sudo ./lightpn-agent.sh status
#   sudo ./lightpn-agent.sh uninstall
#
# 所有文件(二进制/身份)集中安装在用户主目录下的 ~/lightpn,只有 systemd
# 单元放在 /etc/systemd/system。系统里装了什么一目了然,卸载即净。
# systemd 单元内嵌在本脚本里,服务器上只需要「二进制 + 本脚本」两个文件。
set -euo pipefail

SERVICE=lightpn-agent
UNIT=/etc/systemd/system/lightpn-agent.service
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
  BIN_DST="$APP_DIR/lightpn-agent"
  DATA_DIR="$APP_DIR/identity"
}
set_paths "$(detect_app_dir)"

usage() {
  cat <<EOF
用法: lightpn-agent.sh <命令> [选项]

  install [--hub <ip:port> --token <token>] [--socks-port <端口>]
          [--dir <安装目录>] [--bin <路径>]
                安装到 $APP_DIR 并写 systemd 单元;若给了 --hub/--token 且
                本机尚未入网,则顺带完成 enroll 并启动。--socks-port 让本
                节点开启 overlay SOCKS5(参与出口功能必需,常用 1080)。
                可重复执行(升级二进制/增删 --socks-port 时重跑即可)。
  enroll --hub <ip:port> --token <token>
                入网(token 在 hub 面板生成,一次性),成功后自动启动服务
  start / stop / restart / status
  logs [-f]     查看日志(-f 持续跟踪)
  uninstall [--keep-data] [--yes]
                停止并移除服务、单元、WG 设备与整个 $APP_DIR(含身份密钥,
                需输入 yes 确认);--keep-data 只删二进制与单元,保留身份。
                推荐先在 hub 面板删除该节点,让 hub 完成级联清理。

要求: 放行本机 WG UDP 端口(默认 51820)。
EOF
}

die() { echo "lightpn-agent.sh: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "需要 root 权限,请用 sudo 运行"; }
enrolled() { [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; }

write_unit() {
  local socks_args="$1"
  cat >"$UNIT" <<EOF
[Unit]
Description=LightPN agent (edge node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# To let this node act as (or use) an exit, append: --socks-port 1080
# It binds the exit SOCKS5 on the overlay IP and advertises it to the hub.
ExecStart=$BIN_DST --data-dir $DATA_DIR$socks_args
Restart=always
RestartSec=3
# The agent needs CAP_NET_ADMIN to manage the WireGuard device.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
# Hardening. ProtectSystem=strict keeps the filesystem read-only except
# the app dir under the user's home (hence no ProtectHome, which would
# mask /home and /root entirely).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR
PrivateTmp=yes

# Exit code 0 after a hub-side kick means "do not restart".
RestartPreventExitStatus=0

[Install]
WantedBy=multi-user.target
EOF
}

do_enroll() {
  local hub="$1" token="$2"
  echo "==> 入网: hub=$hub"
  "$BIN_DST" enroll --hub "$hub" --token "$token" --data-dir "$DATA_DIR"
}

cmd_install() {
  need_root
  local bin_src="$SCRIPT_DIR/lightpn-agent" hub="" token="" socks_port=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --hub)        hub="${2:?--hub 需要参数}"; shift 2 ;;
      --token)      token="${2:?--token 需要参数}"; shift 2 ;;
      --socks-port) socks_port="${2:?--socks-port 需要参数}"; shift 2 ;;
      --dir)        set_paths "${2:?--dir 需要参数}"; shift 2 ;;
      --bin)        bin_src="${2:?--bin 需要参数}"; shift 2 ;;
      *) die "未知选项: $1" ;;
    esac
  done
  [ -f "$bin_src" ] || die "找不到二进制 $bin_src(把 lightpn-agent 与本脚本放同一目录,或用 --bin 指定)"

  echo "==> 安装到 $APP_DIR"
  mkdir -p "$APP_DIR"
  # 先停服务再覆盖,避免 "text file busy";源与目标是同一文件则跳过
  systemctl stop "$SERVICE" 2>/dev/null || true
  if ! [ "$bin_src" -ef "$BIN_DST" ]; then
    install -m 755 "$bin_src" "$BIN_DST"
  fi

  echo "==> 安装 systemd 单元 $UNIT"
  local socks_args=""
  [ -n "$socks_port" ] && socks_args=" --socks-port $socks_port"
  write_unit "$socks_args"
  systemctl daemon-reload

  if ! enrolled; then
    if [ -n "$hub" ] && [ -n "$token" ]; then
      do_enroll "$hub" "$token"
    else
      cat <<EOF

安装完成,但本机尚未入网。在 hub 面板生成一次性 token 后执行:
  sudo $0 enroll --hub <hub公网IP>:7440 --token lp_xxxx
EOF
      return 0
    fi
  fi

  echo "==> 启动服务"
  systemctl enable --now "$SERVICE"
  systemctl --no-pager --lines 0 status "$SERVICE" || true
  echo
  echo "记得放行本机 WG UDP 端口(默认 51820),否则 link 会是 degraded。"
}

cmd_enroll() {
  need_root
  local hub="" token=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --hub)   hub="${2:?--hub 需要参数}"; shift 2 ;;
      --token) token="${2:?--token 需要参数}"; shift 2 ;;
      *) die "未知选项: $1" ;;
    esac
  done
  [ -n "$hub" ] && [ -n "$token" ] || die "用法: $0 enroll --hub <ip>:7440 --token <token>"
  [ -x "$BIN_DST" ] || die "尚未安装,先执行: sudo $0 install"
  enrolled && die "本机已入网($DATA_DIR 非空);如需重新入网,先 uninstall 或清空身份目录"
  do_enroll "$hub" "$token"
  systemctl enable --now "$SERVICE"
  echo "已启动。"
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
  # 移除内核 WG 设备(若还在)
  ip link del lightpn0 2>/dev/null || true

  if [ "$keep_data" = 1 ]; then
    rm -f "$BIN_DST"
    echo "已保留身份目录 $DATA_DIR。"
  else
    echo "即将删除整个 $APP_DIR(含节点身份证书与私钥)。"
    if [ "$yes" != 1 ]; then
      read -rp "确认删除请输入 yes: " ans
      [ "$ans" = yes ] || { echo "已跳过数据删除(服务与单元已移除)。"; exit 0; }
    fi
    rm -rf "$APP_DIR"
    echo "已删除 $APP_DIR。"
  fi
  echo "卸载完成。若 hub 仍在运行,请在面板删除本节点,让 hub 完成级联清理(移除对端 peer、吊销证书、回收 overlay IP)。"
}

case "${1:-}" in
  install)   shift; cmd_install "$@" ;;
  enroll)    shift; cmd_enroll "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  start)     need_root; systemctl start "$SERVICE"; echo "已启动" ;;
  stop)      need_root; systemctl stop "$SERVICE"; echo "已停止" ;;
  restart)   need_root; systemctl restart "$SERVICE"; echo "已重启" ;;
  status)    systemctl --no-pager status "$SERVICE" || true ;;
  logs)      shift; journalctl -u "$SERVICE" -n 100 "$@" ;;
  -h|--help|help|"") usage ;;
  *) usage; die "未知命令: $1" ;;
esac
