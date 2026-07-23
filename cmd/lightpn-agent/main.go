// lightpn-agent is the LightPN edge node daemon.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/gitter-hub-blip/lightpn/internal/agent"
)

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll":
			enroll(os.Args[2:])
			return
		case "set-view-pass":
			setViewPass(os.Args[2:])
			return
		case "clear-view-pass":
			clearViewPass(os.Args[2:])
			return
		case "svc-add":
			svcAdd(os.Args[2:])
			return
		case "svc-del":
			svcDel(os.Args[2:])
			return
		case "svc-list":
			svcList(os.Args[2:])
			return
		}
	}
	run(os.Args[1:])
}

// svcAdd registers a systemd unit under an operator-chosen alias for hub
// remote control, with an optional config-file path the panel's conf_get
// view will read. Registration is local-CLI-only by design: the hub can
// never add, rename, or remove entries, and only aliases go on the wire —
// the conf path in particular never comes from the hub.
func svcAdd(args []string) {
	fs := flag.NewFlagSet("svc-add", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	unit := fs.String("unit", "", "systemd unit 名(如 xray.service)")
	alias := fs.String("alias", "", "别名(面板与协议中代表该服务,1-32 位小写字母/数字/-)")
	conf := fs.String("conf", "", "该软件配置文件的绝对路径(可选,面板「拉取配置」会显示)")
	fs.Parse(args)

	svc := agent.NewSvcManager()
	reader := bufio.NewReader(os.Stdin)
	if *unit == "" {
		if found := agent.DetectSvcCandidates(svc); len(found) > 0 {
			fmt.Println("检测到的常见翻墙软件 unit(仅供参考,可输入其他):")
			for i, u := range found {
				fmt.Printf("  %d) %s\n", i+1, u)
			}
			fmt.Print("输入编号或完整 unit 名: ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(found) {
				*unit = found[n-1]
			} else {
				*unit = line
			}
		} else {
			fmt.Print("systemd unit 名(如 xray.service): ")
			line, _ := reader.ReadString('\n')
			*unit = strings.TrimSpace(line)
		}
	}
	if *alias == "" {
		fmt.Print("别名(如 ssrust): ")
		line, _ := reader.ReadString('\n')
		*alias = strings.TrimSpace(line)
	}
	confAsked := *conf != ""
	if !confAsked {
		fmt.Print("配置文件绝对路径(可选,面板「拉取配置」会显示该文件,如 /etc/caddy/Caddyfile;回车跳过): ")
		line, _ := reader.ReadString('\n')
		*conf = strings.TrimSpace(line)
	}
	if !svc.Exists(*unit) {
		fatal("systemd 不认识 unit %q(systemctl show 查不到);未登记", *unit)
	}
	if err := agent.AddSvc(*dataDir, *alias, *unit, *conf); err != nil {
		fatal("%v", err)
	}
	if *conf == "" {
		fmt.Printf("已登记 %s → %s。\n", *alias, *unit)
	} else {
		fmt.Printf("已登记 %s → %s(配置: %s)。\n", *alias, *unit, *conf)
		if fi, err := os.Stat(*conf); err != nil {
			fmt.Printf("提醒:该路径当前无法读取(%v),面板会显示读取错误;确认路径无误或稍后建好文件即可。\n", err)
		} else if fi.IsDir() {
			fmt.Println("提醒:该路径是目录,目前只支持单个文件,面板会显示错误。")
		}
	}
	if !agent.HasViewKey(*dataDir) {
		fmt.Println("注意:本机尚未设置配置查看密码(set-view-pass),远程开关不会激活 —— 无密码则指令无法验真。")
	}
}

func svcDel(args []string) {
	fs := flag.NewFlagSet("svc-del", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	alias := fs.String("alias", "", "要删除的别名")
	fs.Parse(args)
	if *alias == "" {
		fatal("usage: lightpn-agent svc-del --alias <name>")
	}
	if err := agent.DelSvc(*dataDir, *alias); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("已删除别名 %s。\n", *alias)
}

func svcList(args []string) {
	fs := flag.NewFlagSet("svc-list", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	fs.Parse(args)
	reg, err := agent.LoadSvcReg(*dataDir)
	if err != nil {
		fatal("%v", err)
	}
	if len(reg) == 0 {
		fmt.Println("尚未登记任何服务。用 svc-add 登记。")
		return
	}
	svc := agent.NewSvcManager()
	for _, e := range reg {
		active, enabled := svc.Status(e.Unit)
		conf := e.Conf
		if conf == "" {
			conf = "-"
		}
		fmt.Printf("%-20s %-30s %-10s %s\n", e.Alias, e.Unit, active+"/"+enabled, conf)
	}
}

// setViewPass configures the conf-view password: panel conf_get replies are
// end-to-end encrypted with a key derived from it (decrypted in the
// operator's browser; hub and any fronting proxy see only ciphertext).
func setViewPass(args []string) {
	fs := flag.NewFlagSet("set-view-pass", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	fs.Parse(args)
	fmt.Fprint(os.Stderr, "配置查看密码(面板查看本机配置时输入,hub 无法解密): ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("read password: %v", err)
	}
	fmt.Fprint(os.Stderr, "再输入一次确认: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("read password: %v", err)
	}
	if string(p1) != string(p2) {
		fatal("两次输入不一致")
	}
	if len(p1) == 0 {
		fatal("密码不能为空(取消加密请用 clear-view-pass)")
	}
	if err := agent.SetViewPassword(*dataDir, string(p1)); err != nil {
		fatal("%v", err)
	}
	fmt.Println("查看密码已设置;面板拉取配置将端到端加密,浏览器端输入该密码解密。")
}

func clearViewPass(args []string) {
	fs := flag.NewFlagSet("clear-view-pass", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	fs.Parse(args)
	if err := agent.ClearViewPassword(*dataDir); err != nil {
		fatal("%v", err)
	}
	fmt.Println("查看密码已清除;面板拉取配置恢复为明文(前端打码)。")
}

func enroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	hubAddr := fs.String("hub", "", "hub control address host:port (required)")
	token := fs.String("token", "", "one-time enrollment token (required)")
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	fs.Parse(args)
	if *hubAddr == "" || *token == "" {
		fatal("usage: lightpn-agent enroll --hub <ip>:7440 --token <token>")
	}
	if _, err := agent.LoadIdentity(*dataDir); err == nil {
		fatal("identity already exists in %s — this machine is already enrolled", *dataDir)
	}
	id, err := agent.Enroll(*hubAddr, *token, *dataDir)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("enrolled: node %s, overlay %s\nstart the agent with: lightpn-agent --data-dir %s\n",
		id.NodeID, id.OverlayIP, *dataDir)
}

func run(args []string) {
	fs := flag.NewFlagSet("lightpn-agent", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	wgPort := fs.Int("wg-port", 51820, "WireGuard listen port")
	heartbeat := fs.Int("heartbeat-s", 15, "heartbeat period seconds")
	socksPort := fs.Int("socks-port", 0, "enable exit SOCKS5 on this port (bound to the overlay IP); 0 = disabled")
	socksListen := fs.String("socks-listen", "", "override exit SOCKS5 bind address (default <overlay-ip>:<socks-port>)")
	exitVia := fs.String("exit-via", "", "pin egress through this overlay SOCKS address, e.g. 100.100.0.9:1080 (overrides hub-driven exit; for testing)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	id, err := agent.LoadIdentity(*dataDir)
	if err != nil {
		fatal("no identity in %s — enroll first: lightpn-agent enroll --hub <ip>:7440 --token <token>", *dataDir)
	}
	wg, err := agent.NewWGManager()
	if err != nil {
		fatal("%v", err)
	}

	a := &agent.Agent{
		ID:              id,
		WG:              wg,
		Log:             log,
		WGPort:          *wgPort,
		HeartbeatPeriod: time.Duration(*heartbeat) * time.Second,
		Svc:             agent.NewSvcManager(),
	}

	// Exit SOCKS5: enable it if a port is set, a bind is overridden, or a
	// manual upstream is pinned.
	if *socksPort > 0 || *socksListen != "" || *exitVia != "" {
		ec, err := agent.NewExitController(log, *exitVia)
		if err != nil {
			fatal("exit controller: %v", err)
		}
		a.Exit = ec
		bind := *socksListen
		port := *socksPort
		if bind == "" {
			overlayIP := strings.SplitN(id.OverlayIP, "/", 2)[0]
			if port == 0 {
				port = 1080
			}
			bind = net.JoinHostPort(overlayIP, strconv.Itoa(port))
		} else if port == 0 {
			if _, p, err := net.SplitHostPort(bind); err == nil {
				port, _ = strconv.Atoi(p)
			}
		}
		a.SocksListen = bind
		// Only advertise the port to the hub (so other nodes may exit via
		// us) when the listener is overlay-reachable, i.e. not loopback.
		if host, _, err := net.SplitHostPort(bind); err == nil && !isLoopback(host) {
			a.SocksPort = port
		}
	}

	err = a.Run()
	if errors.Is(err, agent.ErrKicked) {
		log.Warn("removed by hub administrator; identity destroyed")
		os.Exit(0)
	}
	fatal("%v", err)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lightpn-agent: "+format+"\n", args...)
	os.Exit(1)
}
