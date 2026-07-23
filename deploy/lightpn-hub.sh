#!/usr/bin/env bash
# LightPN hub 交互式管理脚本(systemd Linux)。
# 与 lightpn-hub 二进制放在同一目录,以 root 运行后按菜单编号操作:
#
#   sudo ./lightpn-hub.sh
#
# 所有文件(二进制/配置/数据)集中安装在用户主目录下的 ~/lightpn,
# 只有 systemd 单元放在 /etc/systemd/system。系统里装了什么一目了然,
# 卸载时删掉单元 + 整个目录即净。
# systemd 单元内嵌在本脚本里,服务器上只需要「二进制 + 本脚本」两个文件。
set -uo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; blue='\033[0;34m'; plain='\033[0m'
err()  { echo -e "${red}$*${plain}"; }
ok()   { echo -e "${green}$*${plain}"; }
warn() { echo -e "${yellow}$*${plain}"; }

SERVICE=lightpn-hub
UNIT=/etc/systemd/system/lightpn-hub.service
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
  BIN_DST="$APP_DIR/lightpn-hub"
  DATA_DIR="$APP_DIR/hub-data"
  CONF="$APP_DIR/hub.json"
}
set_paths "$(detect_app_dir)"

installed() { [ -f "$UNIT" ] && [ -f "$BIN_DST" ]; }

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

do_install() {
  # 安装目录:首次安装可自定义,已安装则沿用 unit 中的目录做升级
  if installed; then
    ok "检测到已安装于 $APP_DIR,本次执行升级/更新配置。"
  else
    local d
    read -rp "安装目录 (回车使用默认 $APP_DIR): " d
    if [ -n "$d" ]; then
      # systemd 要求 ExecStart/ReadWritePaths 为绝对路径;规整用户输入,
      # 否则相对路径会生成 systemd 拒绝的坏 unit。
      d="${d/#\~/$HOME}"
      case "$d" in
        /*) : ;;
        *)  d="$(pwd)/$d" ;;
      esac
      d="$(realpath -m "$d" 2>/dev/null || echo "$d")"
      set_paths "$d"
    fi
  fi

  # 二进制:默认取脚本同目录下的 lightpn-hub
  local bin_src="$SCRIPT_DIR/lightpn-hub"
  if [ ! -f "$bin_src" ]; then
    warn "脚本目录下没有 lightpn-hub 二进制。"
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

  # public_addr:agent 入网后回连 hub 的地址,强烈建议显式配置
  local addr
  if [ -f "$CONF" ]; then
    echo -e "当前配置 $CONF: ${yellow}$(cat "$CONF")${plain}"
    read -rp "hub 公网地址 (ip:port,回车保持现状): " addr
  else
    warn "public_addr 是 agent 入网后回连 hub 的地址,强烈建议显式配置。"
    read -rp "hub 公网地址 (ip:port,如 203.0.113.10:7440,回车跳过): " addr
  fi
  if [ -n "$addr" ]; then
    printf '{ "public_addr": "%s" }\n' "$addr" >"$CONF"
    ok "已写入 $CONF"
  fi

  echo "==> 安装 systemd 单元 $UNIT"
  write_unit
  systemctl daemon-reload

  if [ ! -f "$DATA_DIR/hub.db" ]; then
    echo "==> 首次安装,设置管理员密码(至少 8 位)"
    "$BIN_DST" admin set-password --data-dir "$DATA_DIR" || { err "设置密码失败。"; return 1; }
  fi

  echo "==> 启动服务"
  systemctl enable --now "$SERVICE" || { err "启动失败,可用菜单「查看日志」排查。"; return 1; }
  systemctl --no-pager --lines 0 status "$SERVICE" || true

  echo
  ok "安装完成。接下来:"
  echo "  1. 防火墙放行 7440/tcp(控制通道);不要放行 7441(面板只绑 127.0.0.1)。"
  echo "  2. 面板经隧道/反代访问 http://127.0.0.1:7441(推荐 Cloudflare Tunnel + Access)。"
  echo "  3. 在面板生成一次性 token,到边缘机器上运行 sudo ./lightpn-agent.sh 选择「安装」。"
}

do_password() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  "$BIN_DST" admin set-password --data-dir "$DATA_DIR"
}

# 备份数据目录(SQLite + CA 私钥)与配置。CA 是全网信任根,丢失即全网
# 重新入网,这是唯一的灾难恢复凭据 —— 打包时会热备(hub 无需停机,SQLite
# WAL 下 tar 得到的是一致快照的近似;要绝对一致可先停服务再备份)。
do_backup() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  [ -d "$DATA_DIR" ] || { err "数据目录 $DATA_DIR 不存在,无可备份。"; return 1; }
  local default_dir dest
  default_dir="$(default_app_dir)/.."
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    default_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  else
    default_dir="$HOME"
  fi
  read -rp "备份保存目录 (回车用 $default_dir): " dest
  [ -n "$dest" ] || dest="$default_dir"
  if [ ! -d "$dest" ]; then
    mkdir -p "$dest" || { err "无法创建 $dest。"; return 1; }
  fi
  local stamp file
  stamp="$(date +%Y%m%d-%H%M%S)"
  file="$dest/lightpn-hub-backup-$stamp.tar.gz"
  # 打包数据目录和配置(都在 APP_DIR 下,用相对路径避免绝对路径泄进包)。
  echo "==> 打包 $DATA_DIR$([ -f "$CONF" ] && echo " 与 $CONF")"
  if tar -czf "$file" -C "$APP_DIR" \
        "$(basename "$DATA_DIR")" \
        $([ -f "$CONF" ] && basename "$CONF"); then
    chmod 600 "$file"
    # 尽量把属主还给发起 sudo 的用户,免得备份文件是 root 属主难管理。
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
      chown "$SUDO_USER" "$file" 2>/dev/null || true
    fi
    ok "已备份到 $file"
    warn "该包含 CA 私钥与全部节点注册信息,权限已设 600 —— 请转移到安全位置妥善保管,勿随意分发。"
  else
    err "打包失败。"
    return 1
  fi
}

do_uninstall() {
  installed || warn "未检测到完整安装,仍将尽量清理残留。"
  echo "==> 停止并移除服务"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload

  echo
  warn "数据目录 $DATA_DIR 内有 SQLite 和 CA 密钥。"
  warn "CA 销毁后所有 agent 证书作废、无法再撮合,删除不可逆!"
  local ans
  read -rp "连同数据一起删除整个 $APP_DIR ? (输入 yes 删除,回车只删程序保留数据): " ans
  if [ "$ans" = yes ]; then
    rm -rf "$APP_DIR"
    ok "已删除 $APP_DIR。"
  else
    rm -f "$BIN_DST"
    ok "已保留数据 $DATA_DIR 与配置 $CONF(重装后可继续使用)。"
  fi
  echo "卸载完成。别忘了逐台清理边缘节点(sudo ./lightpn-agent.sh 选「完全卸载」)。"
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
  echo -e "目录: ${blue}$APP_DIR${plain}"
}

pause() { echo; read -rp "按回车返回菜单 ..." _; }

while true; do
  echo
  echo -e "${green}========================================${plain}"
  echo -e "${green}         LightPN hub 管理脚本${plain}"
  echo -e "${green}========================================${plain}"
  status_line
  echo "----------------------------------------"
  echo -e "  ${blue}1.${plain} 安装 / 升级(可修改公网地址)"
  echo -e "  ${blue}2.${plain} 重设管理员密码"
  echo -e "  ${blue}3.${plain} 备份数据(SQLite + CA + 配置)"
  echo -e "  ${blue}4.${plain} 启动"
  echo -e "  ${blue}5.${plain} 停止"
  echo -e "  ${blue}6.${plain} 重启"
  echo -e "  ${blue}7.${plain} 查看运行状态"
  echo -e "  ${blue}8.${plain} 查看最近日志"
  echo -e "  ${blue}9.${plain} 实时跟踪日志(Ctrl+C 返回菜单)"
  echo -e "  ${blue}10.${plain} 完全卸载"
  echo -e "  ${blue}0.${plain} 退出"
  echo "----------------------------------------"
  read -rp "请输入编号: " choice
  echo
  case "$choice" in
    1) do_install; pause ;;
    2) do_password; pause ;;
    3) do_backup; pause ;;
    4) systemctl start "$SERVICE" && ok "已启动" || err "启动失败"; pause ;;
    5) systemctl stop "$SERVICE" && ok "已停止" || err "停止失败"; pause ;;
    6) systemctl restart "$SERVICE" && ok "已重启" || err "重启失败"; pause ;;
    7) systemctl --no-pager status "$SERVICE" || true; pause ;;
    8) journalctl -u "$SERVICE" -n 100 --no-pager || true; pause ;;
    9) trap : INT; journalctl -u "$SERVICE" -n 20 -f || true; trap - INT ;;
    10) do_uninstall; pause ;;
    0) exit 0 ;;
    *) err "无效编号: $choice" ;;
  esac
done
