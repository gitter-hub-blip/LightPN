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
# /usr/local/bin 同时在普通 PATH 和 sudo 的 secure_path 上,把裸命令
# lightpn-agent 放这里,hub 面板给的一步到位命令加不加 sudo 都能找到。
LAUNCHER=/usr/local/bin/lightpn-agent
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

# 在 /usr/local/bin 放一个薄封装:解决两件事——
#   1. sudo 的 secure_path 覆盖了 /usr/local/bin,裸命令 lightpn-agent
#      加不加 sudo 都能找到(二进制本体仍在 ~/lightpn,不污染系统路径);
#   2. hub 面板给的一步到位命令不带 --data-dir,这里自动补上与 service
#      一致的目录,避免身份写到默认 /var/lib 而 service 读不到。
# 用户若显式传了 --data-dir,则原样透传不覆盖。
write_launcher() {
  cat >"$LAUNCHER" <<EOF
#!/usr/bin/env bash
# 由 lightpn-agent.sh 自动生成,请勿手改。指向 $BIN_DST。
bin="$BIN_DST"
data_dir="$DATA_DIR"
for a in "\$@"; do
  case "\$a" in --data-dir|--data-dir=*) exec "\$bin" "\$@" ;; esac
done
exec "\$bin" "\$@" --data-dir "\$data_dir"
EOF
  chmod 755 "$LAUNCHER"
}

write_unit() {
  local socks_args="$1" wg_args="$2"
  cat >"$UNIT" <<EOF
[Unit]
Description=LightPN agent (edge node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# --socks-port 1080 makes this node an exit (binds SOCKS5 on the overlay IP,
# advertised to the hub). --wg-port <N> overrides the WireGuard listen port
# (default 51820); the hub advertises <observed-public-IP>:<N> to peers, so
# open N/udp inbound and don't put it behind a port-translating NAT.
ExecStart=$BIN_DST --data-dir $DATA_DIR$socks_args$wg_args
Restart=always
RestartSec=3
# CAP_NET_ADMIN drives the WireGuard device. CAP_DAC_READ_SEARCH lets the
# root service traverse the 0750 /home/<user> dir to reach its identity
# under the app dir: capping the bounding set at CAP_NET_ADMIN alone strips
# root of DAC-override, so it can't enter /home/<user> and fails with
# "no identity" even though it runs as root and the files are present
# (a foreground root keeps full caps, which is why it worked there).
# DAC_READ_SEARCH only bypasses read/traverse checks, not write, so the
# hardening loss is minimal.
AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
# Hardening. ProtectSystem=full locks /usr, /boot and /etc read-only but
# leaves /home alone, so the agent reads/writes its identity under the app
# dir directly. Do NOT use strict + ReadWritePaths=$APP_DIR here: bind-
# mounting a /home subdir into the read-only namespace made the identity
# unreadable inside the service on some hosts (identity present on disk,
# service still failed with "no identity"). No ProtectHome either, which
# would mask /home entirely.
NoNewPrivileges=yes
ProtectSystem=full
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

# 配置查看密码:设置后,面板「拉取配置」看到的是端到端加密的密文,
# 浏览器端输入本密码解密;hub 与其前置代理(如 CDN)拿不到明文。
prompt_view_pass() {
  local ans
  echo "可为本机设置「配置查看密码」:面板查看本机翻墙软件配置时须在浏览器"
  echo "输入该密码解密,hub 与其前面的 CDN 全程只见密文。"
  read -rp "现在设置吗? (y/N): " ans
  case "$ans" in
    y|Y) "$BIN_DST" set-view-pass --data-dir "$DATA_DIR" || warn "设置失败,可稍后在菜单重试。" ;;
    *)   warn "已跳过。面板将以明文查看配置(仅前端打码);可稍后在菜单设置。" ;;
  esac
}

do_install() {
  # 安装目录:首次安装可自定义,已安装则沿用 unit 中的目录做升级
  if installed; then
    ok "检测到已安装于 $APP_DIR,本次执行升级/更新配置。"
  else
    local d
    read -rp "安装目录 (回车使用默认 $APP_DIR): " d
    if [ -n "$d" ]; then
      # systemd 的 ExecStart/ReadWritePaths 要求绝对路径。用户可能输入相对
      # 路径(如 "1")或含 ~ 的路径,统一规整为绝对路径,否则会生成
      # ExecStart=1/lightpn-agent 这种 systemd 拒绝的坏 unit。
      d="${d/#\~/$HOME}"                       # 展开开头的 ~
      case "$d" in
        /*) : ;;                               # 已是绝对路径
        *)  d="$(pwd)/$d" ;;                    # 相对路径 → 相对当前目录转绝对
      esac
      # 折叠多余的 . 和尾部斜杠(realpath -m 不要求路径已存在)
      d="$(realpath -m "$d" 2>/dev/null || echo "$d")"
      set_paths "$d"
    fi
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

  # 放置 /usr/local/bin/lightpn-agent 封装,让 hub 面板的一步到位入网
  # 命令(裸 lightpn-agent、无 --data-dir)在 sudo 下也能直接跑。
  echo "==> 安装启动器 $LAUNCHER"
  write_launcher || warn "写入 $LAUNCHER 失败(不影响 service,但裸命令入网可能 not found)。"

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

  # WG 端口:其他节点入站连本机走这个 UDP 端口。默认 51820,仅当默认被占用、
  # 或防火墙/端口映射只放行特定端口时才自定义。hub 会向对端通告
  # <本机公网IP>:<此端口>,故须放行 <端口>/udp 且不要落在端口转换的 NAT 后。
  local wg_port wg_args="" wg_effective=51820
  echo "WireGuard 端口(其他节点入站连本机用):默认 51820,回车即用默认;"
  echo "仅当默认端口被占用,或防火墙/端口映射只放行特定端口时才需自定义。"
  while true; do
    read -rp "WG 端口 (回车用默认 51820): " wg_port
    [ -z "$wg_port" ] && break
    if [[ "$wg_port" =~ ^[0-9]+$ ]] && [ "$wg_port" -ge 1 ] && [ "$wg_port" -le 65535 ]; then
      wg_args=" --wg-port $wg_port"
      wg_effective="$wg_port"
      break
    fi
    err "端口须是 1-65535 的数字。"
  done

  echo "==> 安装 systemd 单元 $UNIT"
  write_unit "$socks_args" "$wg_args"
  systemctl daemon-reload

  if ! enrolled; then
    local ans
    read -rp "本机尚未入网,现在入网吗? (y/N): " ans
    case "$ans" in
      y|Y) prompt_enroll || { warn "入网失败,可稍后在菜单选「入网」重试。"; return 1; } ;;
      *)   warn "已跳过入网。之后在菜单选「入网」完成。"; return 0 ;;
    esac
    prompt_view_pass
  fi

  echo "==> 启动服务"
  systemctl enable --now "$SERVICE" || { err "启动失败,可用菜单「查看日志」排查。"; return 1; }
  systemctl --no-pager --lines 0 status "$SERVICE" || true
  echo
  ok "安装完成。记得放行本机 WG UDP 端口($wg_effective/udp,主机防火墙 + 云安全组),否则 link 会是 degraded。"
}

do_enroll() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  enrolled && { err "本机已入网($DATA_DIR 非空);如需重新入网,先「完全卸载」。"; return 1; }
  prompt_enroll || return 1
  prompt_view_pass
  systemctl enable --now "$SERVICE" && ok "已启动。" || err "启动失败"
}

# 远程开关服务:登记本机 systemd unit + 别名 + 可选配置文件路径。协议里
# 只走别名,hub 永远拿不到 unit 名和路径,也没有任何途径增删登记 —— 一切
# 以本机 services.json 为准。登记了配置路径的软件,面板「拉取配置」会一并
# 显示该文件(内置自动检测覆盖不到的软件靠这个变相兼容,如 naive/caddy)。
do_svc() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  enrolled  || { err "尚未入网,身份目录为空。"; return 1; }
  echo "当前登记的服务(别名 / unit / 状态 / 配置路径):"
  "$BIN_DST" svc-list --data-dir "$DATA_DIR"
  echo
  local ans
  # 回车即只查看退出;上面已经列出当前登记。
  read -rp "登记(a)/删除(d)/仅查看(回车退出): " ans
  case "$ans" in
    a|A) "$BIN_DST" svc-add --data-dir "$DATA_DIR" ;;
    d|D) local alias
         read -rp "要删除的别名: " alias
         [ -n "$alias" ] && "$BIN_DST" svc-del --data-dir "$DATA_DIR" --alias "$alias" ;;
  esac
}

do_view_pass() {
  installed || { err "尚未安装,请先执行「安装」。"; return 1; }
  enrolled  || { err "尚未入网,身份目录为空。"; return 1; }
  local ans
  if [ -f "$DATA_DIR/view.key" ]; then
    echo -e "当前:${green}已设置${plain}配置查看密码。"
    read -rp "重设(r)/清除(c)/取消(回车): " ans
    case "$ans" in
      r|R) "$BIN_DST" set-view-pass --data-dir "$DATA_DIR" ;;
      c|C) "$BIN_DST" clear-view-pass --data-dir "$DATA_DIR" ;;
    esac
  else
    echo -e "当前:${yellow}未设置${plain}(面板明文查看,仅前端打码)。"
    "$BIN_DST" set-view-pass --data-dir "$DATA_DIR"
  fi
}

do_uninstall() {
  installed || warn "未检测到完整安装,仍将尽量清理残留。"
  echo "==> 停止并移除服务"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  # 仅当封装确实指向本安装目录的二进制时才移除,避免误删他处安装的启动器。
  if [ -f "$LAUNCHER" ] && grep -q "bin=\"$BIN_DST\"" "$LAUNCHER" 2>/dev/null; then
    rm -f "$LAUNCHER"
  fi
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
  echo -e "  ${blue}10.${plain} 配置查看密码(设置/重设/清除)"
  echo -e "  ${blue}11.${plain} 远程开关/配置查看服务(登记 unit+配置路径+别名)"
  echo -e "  ${blue}0.${plain} 退出"
  echo "----------------------------------------"
  read -rp "请输入编号: " choice
  echo
  case "$choice" in
    1) do_install; pause ;;
    2) do_enroll; pause ;;
    10) do_view_pass; pause ;;
    11) do_svc; pause ;;
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
