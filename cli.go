package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func demoManager() (*manager, error) {
	root, e := os.MkdirTemp("", "vpswall-demo-")
	if e != nil {
		return nil, e
	}
	m := &manager{root: root, system: filepath.Join(root, "etc"), runtimeDir: filepath.Join(root, "run"), demo: true, now: time.Now, ssh: "192.0.2.40 52341 203.0.113.9 22"}
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-enabled" {
			return "enabled\n", nil
		}
		if name == "ufw" {
			return "Status: active\nDefault: deny (incoming)\n\n[ 1] 22/tcp  ALLOW IN 192.0.2.40\n[ 2] 443/tcp ALLOW IN Anywhere", nil
		}
		return "Демонстрационный режим: системные команды не выполняются.", nil
	}
	ssh, _ := sshRule(m.ssh)
	ssh.Priority = 0
	https, _ := newManaged("allow", "tcp", "443", "any", "Сайт · HTTPS")
	c := managerConfig{Backend: "ufw", Enabled: true, Zone: "public", Policy: "deny", Rules: []managedRule{ssh, https}}
	if e = writeJSON(m.path("manager.json"), c); e != nil {
		return nil, e
	}
	r, _ := newManaged("allow", "tcp", "80", "any", "Обновление сертификата")
	w := window{ID: r.ID, Rule: r, Kind: "daily", Clock: "03:00", Zone: "Europe/Moscow", Seconds: 3600}
	writeJSON(m.path("windows.json"), []window{w})
	return m, nil
}
func main() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("vpswall", version)
		return
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		fmt.Println("VPSWall " + version + " — UFW / firewalld / nftables / iptables\n\nsudo --preserve-env=SSH_CONNECTION vpswall   Терминальная панель\nvpswall --demo                             Безопасная демонстрация UI\nsudo vpswall status                        Состояние\nsudo vpswall confirm CODE                  Подтвердить из нового SSH\nsudo vpswall rollback                      Отменить изменение\nsudo vpswall worker                        Обработать окна портов\nsudo vpswall certbot-open / certbot-close   Хуки Certbot\nsudo vpswall web enable / disable          Локальный веб-сервис\nsudo --preserve-env=SSH_CONNECTION vpswall web token\nvpswall web --demo                         Демонстрация веб-панели\nУстановка: sudo sh ./install.sh")
		return
	}
	webDemo := len(args) == 2 && args[0] == "web" && args[1] == "--demo"
	demo := len(args) == 1 && args[0] == "--demo" || webDemo
	var m *manager
	var e error
	if demo {
		m, e = demoManager()
		if e == nil {
			defer os.RemoveAll(m.root)
		}
	} else {
		if runtime.GOOS != "linux" {
			fail(fmt.Errorf("для управления firewall требуется Linux; UI можно посмотреть через --demo"))
		}
		if os.Geteuid() != 0 {
			fail(fmt.Errorf("запустите через sudo --preserve-env=SSH_CONNECTION vpswall"))
		}
		m = &manager{root: "/var/lib/vpswall", system: "/etc", runtimeDir: "/run/vpswall", run: managerCommand, now: time.Now, ssh: os.Getenv("SSH_CONNECTION")}
		a := &app{state: m.root}
		e = a.init()
	}
	if e != nil {
		fail(e)
	}
	legacy := &app{state: m.root, etc: m.system, run: command, now: m.now, ssh: m.ssh}
	switch {
	case webDemo:
		_, e = m.issueWebToken()
		if e == nil {
			go func() {
				for range time.Tick(time.Second) {
					m.worker(false)
				}
			}()
			e = m.serveWeb(8091)
		}
	case len(args) == 2 && args[0] == "web" && args[1] == "serve":
		e = m.serveWeb(8090)
	case len(args) == 2 && args[0] == "web" && args[1] == "enable":
		e = m.webService(true)
		if e == nil {
			fmt.Println("Веб-панель включена на 127.0.0.1:8090. Получите токен: sudo --preserve-env=SSH_CONNECTION vpswall web token")
		}
	case len(args) == 2 && args[0] == "web" && args[1] == "disable":
		e = m.webService(false)
	case len(args) == 2 && args[0] == "web" && args[1] == "token":
		var token string
		token, e = m.issueWebToken()
		if e == nil {
			fmt.Println("Токен на 8 часов (предыдущий заменён):\n" + token + "\n\nНа вашем компьютере: ssh -N -L 127.0.0.1:8090:127.0.0.1:8090 -p SSH_PORT USER@SERVER\nОткройте http://127.0.0.1:8090 и вставьте токен. Не отправляйте его другим людям.")
		}
	case demo || len(args) == 0:
		p, err := legacy.getPending()
		if err != nil {
			fail(err)
		}
		if p != nil && !demo {
			fail(fmt.Errorf("осталось изменение версии 0.1.0: подтвердите его через confirm %s или выполните rollback", p.Token))
		}
		_, e = tea.NewProgram(newUI(m), tea.WithAltScreen()).Run()
	case len(args) == 1 && args[0] == "status":
		fmt.Println(m.summary())
		c, err := m.config()
		if err == nil {
			var out string
			out, err = m.rawStatus(c)
			fmt.Print(out)
		}
		e = err
	case len(args) == 2 && args[0] == "confirm":
		p, err := legacy.getPending()
		if err != nil {
			e = err
		} else if p != nil {
			e = legacy.confirm(args[1])
		} else {
			e = m.confirm(args[1])
		}
		if e == nil {
			fmt.Println("Подтверждено.")
		}
	case len(args) == 1 && args[0] == "rollback":
		e = legacy.rollback()
		if e == nil {
			e = m.rollback()
		}
	case len(args) == 1 && args[0] == "worker":
		e = m.worker(false)
	case len(args) == 1 && args[0] == "recover":
		e = legacy.rollback()
		if e == nil {
			e = m.rollback()
		}
		if e == nil {
			e = m.worker(true)
		}
	case len(args) == 1 && args[0] == "certbot-open":
		e = m.certbotOpen()
	case len(args) == 1 && args[0] == "certbot-close":
		e = m.certbotClose()
	default:
		e = fmt.Errorf("неизвестная команда; vpswall --help")
	}
	if e != nil {
		fail(e)
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, "Ошибка:", e); os.Exit(1) }
