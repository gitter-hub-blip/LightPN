#!/usr/bin/env bash
# LightPN agent 交互式管理脚本(systemd Linux,内核 ≥ 5.6 内建 WireGuard)。
# 与 lightpn-agent 二进制放在同一目录,以 root 运行后按菜单编号操作:
#
#   sudo ./lightpn-agent.sh
#
# 所有文件(二进制/身份)集中安装在用户主目录下的 ~/lightpn,只有 systemd
# 单元放在 /etc/systemd/system。系统里装了什么一目了然,卸载即净。
# systemd 单元内嵌在本脚本里,服务器上只需要「二进制 + 本脚本」两个文件。
set -uo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; blue='\033[0;34m'; plain='\033[0m'
err()  { echo -e "${red}$*${plain}"; }
ok()   { echo -e "${green}$*${plain}"; }
warn() { echo -e "${yellow}$*${plain}"; }

SERVICE=lightpn-agent
UNIT=/etc/systemd/system/lightpn-agent.service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" = 0 ] || { err "需要 root 权限,请用 sudo 运行"; exit 1; }

# 安装目录默认 <运行 sudo 的用户主目录>/lightpn。已安装过时,一律以 unit
# 里记录的实际路径为准,避免换个用户执行脚本时算出不同目录。
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
  default_app_dir
}
set_paths() {
  APP_DIR="$1"
  BIN_DST="$APP_DIR/lightpn-agent"
  DATA_DIR="$APP_DIR/identity"
}
set_paths "$(detect_app_dir)"

installed() { [ -f "$UNIT" ] && [ -f "$BIN_DST" ]; }
enrolled()  { [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; }

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

# 交互式收集 hub 地址与 token 并执行入网;成功返回 0
prompt_enroll() {
  local hub token
  read -rp "hub 控制地址 (ip:port,如 203.0.113.10:7440): " hub
  [ -n "$hub" ] || { err "hub 地址不能为空。"; return 1; }
  read -rp "一次性 token (在 hub 面板生成,lp_ 开头): " token
  [ -n "$token" ] || { err "token 不能为空。"; return 1; }
  echo "==> 入网: hub=$hub"
  "$BIN_DST" enroll --hub "$hub" --token "$token" --data-dir "$DATA_DIR"
}

do_install() {
  # 安装目录:首次安装可自定义,已安装则沿用 unit 中的目录做升级
  if installed; then
    ok "检测到已安装于 $APP_DIR,本次执行升级/更新配置。"
  else
    local d
    read -rp "安装目录 (回车使用默认 $APP_DIR): " d
    [ -n "$d" ] && set_paths "$d"
  fi

  # 二进制:默认取脚本同目录下的 lightpn-agent
  local bin_src="$SCRIPT_DIR/lightpn-agent"
  if [ ! -f "$bin_src" ]; then
    warn "脚本目录下没有 lightpn-agent 二进制。"
    read -rp "请输入二进制路径: " bin_src
    [ -f "$bin_src" ] || { err "找不到 $bin_src,安装中止。"; return 1; }
  fi

  echo -e "==> 安装到 ${blue}$APP_DIR${plain}"
  mkdir -p "$APP_DIR"
  # 先停服务再覆盖,避免 "text file busy";源与目标是同一文件则跳过
  systemctl stop "$SERVICE" 2>/dev/null || true
  if ! [ "$bin_src" -ef "$BIN_DST" ]; then
    install -m 755 "$bin_src" "$BIN_DST" || { err "复制二进制失败。"; return 1; }
  fi

  # SOCKS 端口:参与出口功能(作为出口,或把本机翻墙出站接进隧道)时必需
  local socks_port socks_args=""
  echo "SOCKS 端口用于出口功能:开启后本节点在 overlay IP 上监听 SOCKS5,"
  echo "并向 hub 通告「我可作为出口」;不用出口功能直接回车。"
  while true; do
    read -rp "SOCKS 端口 (常用 1080,回车不开启): " socks_port
    [ -z "$socks_port" ] && break
    if [[ "$socks_port" =~ ^[0-9]+$ ]] && [ "$socks_port" -ge 1 ] && [ "$socks_port" -le 65535 ]; then
      socks_args=" --socks-port $socks_port"
      break
    fi
    err "端口须是 1-65535 的数字。"
  done

  echo "==> 安装 systemd 单元 $UNIT"
  write_unit "$socks_args"
  systemctl daemon-reload

  if ! enrolled; then
    local ans
    read -rp "本机尚未入网,现在入网吗? (y/N): " ans
    case "$ans" in
      y|Y) prompt_enroll || { warn "入网失败,可稍后在菜单选「入网」重试。"; return 1; } ;;
      *)   warn "已跳过入网。之后在菜单选「入网」完成。"; return 0 ;;
    esac
  fi

  echo "==> 启动服务"
  systemctl enable --now "$SERVICE" || { err "启动失败,可用菜单「查看日志」排查。"; return 1; }
  systemctl --no-pager --lines 0 status "$SERVICE" || true
  echo
  ok "安装完成。记得放行本机 WG UDP 端口(默认 51820),否则 link 会是 degraded。"
}

do_enroll() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  enrolled && { err "本机已入网($DATA_DIR 非空);如需重新入网,先「完全卸载」。"; return 1; }
  prompt_enroll || return 1
  systemctl enable --now "$SERVICE" && ok "已启动。" || err "启动失败"
}

do_uninstall() {
  installed || warn "未检测到完整安装,仍将尽量清理残留。"
  echo "==> 停止并移除服务"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  # 移除内核 WG 设备(若还在)
  ip link del lightpn0 2>/dev/null || true

  echo
  warn "身份目录 $DATA_DIR 内有节点证书与私钥,删除后需重新入网。"
  local ans
  read -rp "连同身份一起删除整个 $APP_DIR ? (输入 yes 删除,回车只删程序保留身份): " ans
  if [ "$ans" = yes ]; then
    rm -rf "$APP_DIR"
    ok "已删除 $APP_DIR。"
  else
    rm -f "$BIN_DST"
    ok "已保留身份目录 $DATA_DIR。"
  fi
  echo "卸载完成。若 hub 仍在运行,请在面板删除本节点,让 hub 完成级联清理(移除对端 peer、吊销证书、回收 overlay IP)。"
}

status_line() {
  if installed; then
    local st
    st="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    if [ "$st" = active ]; then
      echo -e "状态: ${green}已安装,运行中${plain}"
    else
      echo -e "状态: ${yellow}已安装,未运行($st)${plain}"
    fi
  else
    echo -e "状态: ${red}未安装${plain}"
  fi
  if enrolled; then
    echo -e "入网: ${green}已入网${plain}"
  else
    echo -e "入网: ${yellow}未入网${plain}"
  fi
  echo -e "目录: ${blue}$APP_DIR${plain}"
}

pause() { echo; read -rp "按回车返回菜单 ..." _; }

while true; do
  echo
  echo -e "${green}========================================${plain}"
  echo -e "${green}        LightPN agent 管理脚本${plain}"
  echo -e "${green}========================================${plain}"
  status_line
  echo "----------------------------------------"
  echo -e "  ${blue}1.${plain} 安装 / 升级(可修改 SOCKS 端口)"
  echo -e "  ${blue}2.${plain} 入网(enroll,token 在 hub 面板生成)"
  echo -e "  ${blue}3.${plain} 启动"
  echo -e "  ${blue}4.${plain} 停止"
  echo -e "  ${blue}5.${plain} 重启"
  echo -e "  ${blue}6.${plain} 查看运行状态"
  echo -e "  ${blue}7.${plain} 查看最近日志"
  echo -e "  ${blue}8.${plain} 实时跟踪日志(Ctrl+C 返回菜单)"
  echo -e "  ${blue}9.${plain} 完全卸载"
  echo -e "  ${blue}0.${plain} 退出"
  echo "----------------------------------------"
  read -rp "请输入编号: " choice
  echo
  case "$choice" in
    1) do_install; pause ;;
    2) do_enroll; pause ;;
    3) systemctl start "$SERVICE" && ok "已启动" || err "启动失败"; pause ;;
    4) systemctl stop "$SERVICE" && ok "已停止" || err "停止失败"; pause ;;
    5) systemctl restart "$SERVICE" && ok "已重启" || err "重启失败"; pause ;;
    6) systemctl --no-pager status "$SERVICE" || true; pause ;;
    7) journalctl -u "$SERVICE" -n 100 --no-pager || true; pause ;;
    8) trap : INT; journalctl -u "$SERVICE" -n 20 -f || true; trap - INT ;;
    9) do_uninstall; pause ;;
    0) exit 0 ;;
    *) err "无效编号: $choice" ;;
  esac
done
