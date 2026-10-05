package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "0.2.0"
const executable = "/usr/local/bin/vpswall"
const rollbackSeconds = 120

type snapshot struct {
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Active      bool      `json:"active"`
	Description string    `json:"description"`
}
type pending struct {
	Snapshot string    `json:"snapshot"`
	Token    string    `json:"token"`
	SSH      string    `json:"ssh_connection"`
	Deadline time.Time `json:"deadline"`
	Ready    bool      `json:"ready"`
}
type app struct {
	state, etc string
	run        func(string, ...string) (string, error)
	now        func() time.Time
	ssh        string
}

func command(name string, args ...string) (string, error) {
	paths := map[string]string{"ufw": "/usr/sbin/ufw", "systemctl": "/usr/bin/systemctl", "systemd-run": "/usr/bin/systemd-run", "cp": "/usr/bin/cp", "ss": "/usr/bin/ss", "journalctl": "/usr/bin/journalctl"}
	path, ok := paths[name]
	if !ok {
		return "", fmt.Errorf("неизвестная команда: %s", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: превышено время выполнения", name)
	}
	if err != nil {
		return string(out), fmt.Errorf("%s: %w\n%s", name, err, out)
	}
	return string(out), nil
}
func newID() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

var idPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

func (a *app) init() error {
	if err := os.MkdirAll(filepath.Join(a.state, "backups"), 0700); err != nil {
		return err
	}
	for _, path := range []string{a.state, filepath.Join(a.state, "backups")} {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("недопустимый каталог: %s", path)
		}
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	return nil
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (a *app) getPending() (*pending, error) {
	var p pending
	err := readJSON(filepath.Join(a.state, "pending.json"), &p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !idPattern.MatchString(p.Snapshot) || !idPattern.MatchString(p.Token) || p.Deadline.IsZero() {
		return nil, errors.New("повреждено состояние отката; требуется ручная проверка")
	}
	return &p, nil
}
func (a *app) audit(action string) {
	f, err := os.OpenFile(filepath.Join(a.state, "history.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось записать журнал:", err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, a.now().UTC().Format(time.RFC3339), action)
}
func (a *app) backup(description string) (snapshot, error) {
	var s snapshot
	out, err := a.run("ufw", "status")
	if err != nil {
		return s, err
	}
	switch {
	case strings.HasPrefix(strings.TrimSpace(out), "Status: active"):
		s.Active = true
	case strings.HasPrefix(strings.TrimSpace(out), "Status: inactive"):
		s.Active = false
	default:
		return s, errors.New("не удалось определить состояние UFW")
	}
	s.ID, err = newID()
	if err != nil {
		return s, err
	}
	s.Created, s.Description = a.now(), description
	dir := filepath.Join(a.state, "backups", s.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return s, err
	}
	if _, err = a.run("cp", "-a", "--", filepath.Join(a.etc, "ufw"), filepath.Join(dir, "ufw")); err != nil {
		return s, err
	}
	if _, err = a.run("cp", "-a", "--", filepath.Join(a.etc, "default", "ufw"), filepath.Join(dir, "default-ufw")); err != nil {
		return s, err
	}
	err = writeJSON(filepath.Join(dir, "meta.json"), s)
	return s, err
}
func (a *app) loadSnapshot(id string) (snapshot, error) {
	var s snapshot
	if !idPattern.MatchString(id) {
		return s, errors.New("неверный ID копии")
	}
	err := readJSON(filepath.Join(a.state, "backups", id, "meta.json"), &s)
	if err == nil && s.ID != id {
		err = errors.New("ID копии не соответствует метаданным")
	}
	if err == nil {
		for _, name := range []string{"ufw/user.rules", "ufw/user6.rules", "ufw/ufw.conf", "default-ufw"} {
			if _, e := os.Stat(filepath.Join(a.state, "backups", id, name)); e != nil {
				return s, e
			}
		}
	}
	return s, err
}
func (a *app) restore(id string) error {
	s, err := a.loadSnapshot(id)
	if err != nil {
		return err
	}
	source := filepath.Join(a.state, "backups", id)
	stageID, err := newID()
	if err != nil {
		return err
	}
	stage := filepath.Join(a.etc, ".vpswall-stage-"+stageID)
	old := filepath.Join(a.etc, ".vpswall-old-"+stageID)
	if _, err = a.run("cp", "-a", "--", filepath.Join(source, "ufw"), stage); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if !s.Active {
		if _, err = a.run("ufw", "--force", "disable"); err != nil {
			return err
		}
	}
	if err = os.Rename(filepath.Join(a.etc, "ufw"), old); err != nil {
		return err
	}
	if err = os.Rename(stage, filepath.Join(a.etc, "ufw")); err != nil {
		os.Rename(old, filepath.Join(a.etc, "ufw"))
		return err
	}
	// Retain the saved snapshot even after removing this temporary directory.
	defer os.RemoveAll(old)
	if _, err = a.run("cp", "-a", "--remove-destination", "--", filepath.Join(source, "default-ufw"), filepath.Join(a.etc, "default", "ufw")); err != nil {
		return err
	}
	if s.Active {
		_, err = a.run("ufw", "--force", "enable")
	}
	return err
}
func (a *app) cancelTimer() {
	// State is cleared first; any already-started rollback becomes a no-op.
	if _, err := a.run("systemctl", "stop", "vpswall-rollback.timer"); err != nil {
		fmt.Fprintln(os.Stderr, "Предупреждение: таймер не остановлен:", err)
	}
	a.run("systemctl", "reset-failed", "vpswall-rollback.service")
}
func (a *app) rollbackLocked() error {
	p, err := a.getPending()
	if err != nil || p == nil {
		return err
	}
	if err = a.restore(p.Snapshot); err != nil {
		a.audit("ROLLBACK FAILED " + p.Snapshot)
		return err
	}
	if err = os.Remove(filepath.Join(a.state, "pending.json")); err != nil {
		return err
	}
	a.audit("ROLLBACK " + p.Snapshot)
	a.cancelTimer()
	return nil
}
func (a *app) rollback() error {
	unlock, err := lockState(filepath.Join(a.state, "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return a.rollbackLocked()
}
func (a *app) change(description string, perform func() error) (*pending, error) {
	unlock, err := lockState(filepath.Join(a.state, "lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	p, err := a.getPending()
	if err != nil {
		return nil, err
	}
	if p != nil {
		return nil, errors.New("предыдущее изменение ожидает подтверждения или отката")
	}
	out, err := a.run("systemctl", "is-enabled", "vpswall-recover.service")
	if err != nil || strings.TrimSpace(out) != "enabled" {
		return nil, errors.New("сначала выполните install.sh: служба восстановления после перезагрузки не включена")
	}
	// A stale transient service must be gone before scheduling another transaction.
	a.run("systemctl", "stop", "vpswall-rollback.timer", "vpswall-rollback.service")
	a.run("systemctl", "reset-failed", "vpswall-rollback.service")
	s, err := a.backup(description)
	if err != nil {
		return nil, err
	}
	token, err := newID()
	if err != nil {
		return nil, err
	}
	p = &pending{Snapshot: s.ID, Token: token, SSH: a.ssh, Deadline: a.now().Add(rollbackSeconds * time.Second)}
	if err = writeJSON(filepath.Join(a.state, "pending.json"), p); err != nil {
		return nil, err
	}
	if _, err = a.run("systemd-run", "--collect", "--unit=vpswall-rollback", "--on-active=120s", "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=15s", executable, "rollback"); err != nil {
		// Nothing has changed yet. Keep state on removal failure to block mutations.
		removeErr := os.Remove(filepath.Join(a.state, "pending.json"))
		if removeErr != nil {
			return nil, fmt.Errorf("таймер: %v; состояние: %v", err, removeErr)
		}
		return nil, err
	}
	if err = perform(); err != nil {
		rollbackErr := a.rollbackLocked()
		if rollbackErr != nil {
			return nil, fmt.Errorf("изменение: %v; откат: %v (служба повторит попытку)", err, rollbackErr)
		}
		return nil, fmt.Errorf("изменение отменено, конфигурация восстановлена: %w", err)
	}
	if !a.now().Before(p.Deadline) {
		if err = a.rollbackLocked(); err != nil {
			return nil, err
		}
		return nil, errors.New("время применения истекло; выполнен откат")
	}
	p.Ready = true
	if err = writeJSON(filepath.Join(a.state, "pending.json"), p); err != nil {
		rollbackErr := a.rollbackLocked()
		return nil, fmt.Errorf("запись результата: %v; откат: %v", err, rollbackErr)
	}
	a.audit("APPLY " + s.ID + " " + description)
	return p, nil
}
func (a *app) confirm(token string) error {
	unlock, err := lockState(filepath.Join(a.state, "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	p, err := a.getPending()
	if err != nil {
		return err
	}
	if p == nil {
		return errors.New("нет ожидающих изменений")
	}
	if token != p.Token {
		return errors.New("неверный код подтверждения")
	}
	if !p.Ready {
		return errors.New("применение ещё не завершено; подтверждение запрещено")
	}
	if !a.now().Before(p.Deadline) {
		return errors.New("срок подтверждения истёк; выполните откат или дождитесь таймера")
	}
	if p.SSH != "" && (a.ssh == "" || a.ssh == p.SSH) {
		return errors.New("подтвердите из НОВОГО SSH-подключения; sudo должен сохранить SSH_CONNECTION")
	}
	if err = os.Remove(filepath.Join(a.state, "pending.json")); err != nil {
		return err
	}
	a.audit("CONFIRM " + p.Snapshot)
	a.cancelTimer()
	return nil
}

type rule struct{ Action, Protocol, Port, Source, Comment string }

func portValid(s string) bool {
	p := strings.Split(s, ":")
	if len(p) > 2 {
		return false
	}
	vals := []int{}
	for _, v := range p {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != v {
			return false
		}
		vals = append(vals, n)
	}
	return len(vals) == 1 || vals[0] <= vals[1]
}
func (r rule) args() ([]string, error) {
	if r.Action != "allow" && r.Action != "deny" && r.Action != "limit" {
		return nil, errors.New("неверное действие")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return nil, errors.New("протокол должен быть tcp или udp")
	}
	if r.Action == "limit" && r.Protocol != "tcp" {
		return nil, errors.New("ограничение частоты поддерживается только для TCP")
	}
	if !portValid(r.Port) {
		return nil, errors.New("порт: 1–65535 или диапазон, например 8000:8010")
	}
	if r.Source == "" {
		r.Source = "any"
	}
	if r.Source != "any" {
		if addr, e := netip.ParseAddr(r.Source); e == nil {
			if addr.Zone() != "" {
				return nil, errors.New("IP с зоной не поддерживается")
			}
			r.Source = addr.String()
		} else if prefix, e := netip.ParsePrefix(r.Source); e == nil {
			r.Source = prefix.Masked().String()
		} else {
			return nil, errors.New("источник: IP, подсеть CIDR или any")
		}
	}
	if len([]rune(r.Comment)) > 120 || strings.ContainsAny(r.Comment, "\r\n\x00") {
		return nil, errors.New("комментарий: до 120 символов без переводов строк")
	}
	for _, c := range r.Comment {
		if c < 32 || c == 127 {
			return nil, errors.New("управляющие символы в комментарии запрещены")
		}
	}
	args := []string{r.Action, "in", "proto", r.Protocol, "from", r.Source, "to", "any", "port", r.Port}
	if r.Comment != "" {
		args = append(args, "comment", r.Comment)
	}
	return args, nil
}
func (a *app) showPending(p *pending) {
	fmt.Printf("\nПравила применены ВРЕМЕННО. Откат через 120 секунд с начала изменения.\nКопия: %s\n", p.Snapshot)
	fmt.Printf("Откройте новое SSH-подключение и выполните:\n  sudo --preserve-env=SSH_CONNECTION vpswall confirm %s\n", p.Token)
	fmt.Println("Без подтверждения конфигурация восстановится автоматически, включая после перезагрузки.")
}
func (a *app) status() error {
	if fields := strings.Fields(a.ssh); len(fields) == 4 {
		fmt.Printf("Текущее SSH-подключение: источник %s, порт сервера %s\n", fields[0], fields[3])
	}
	for _, args := range [][]string{{"status", "verbose"}, {"status", "numbered"}} {
		out, err := a.run("ufw", args...)
		fmt.Print(out)
		if err != nil {
			return err
		}
	}
	fmt.Println("Сохранённые пользовательские правила (в том числе при выключенном UFW):")
	out, err := a.run("ufw", "show", "added")
	fmt.Print(out)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(a.etc, "default", "ufw"))
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "IPV6=") {
				fmt.Println("Настройка UFW:", line)
			}
		}
	}
	p, err := a.getPending()
	if err != nil {
		return err
	}
	if p != nil {
		fmt.Printf("Ожидается подтверждение до %s. Код: %s\n", p.Deadline.Local().Format("15:04:05 MST"), p.Token)
	}
	fmt.Println("Слушающий порт не обязательно доступен снаружи; firewall хостинга проверяется отдельно.")
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		fmt.Println("Обнаружен Docker: опубликованные порты могут обходить UFW. Проверьте Docker отдельно.")
	}
	return nil
}
func (a *app) listBackups() error {
	entries, err := os.ReadDir(filepath.Join(a.state, "backups"))
	if err != nil {
		return err
	}
	var all []snapshot
	for _, e := range entries {
		if s, err := a.loadSnapshot(e.Name()); err == nil {
			all = append(all, s)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Created.Before(all[j].Created) })
	for _, s := range all {
		fmt.Printf("%s  %s  active=%t  %s\n", s.ID, s.Created.Local().Format("2006-01-02 15:04:05"), s.Active, s.Description)
	}
	return nil
}

type console struct{ reader *bufio.Reader }

func (c *console) ask(prompt string) (string, error) {
	fmt.Print(prompt)
	s, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}
func (c *console) approval(description string) error {
	fmt.Println("\nИзменение:", description)
	s, err := c.ask("Применить с автоматическим откатом? Введите да: ")
	if err != nil {
		return err
	}
	if s != "да" {
		return errors.New("отменено")
	}
	return nil
}
func (a *app) applyUFW(c *console, description string, args ...string) error {
	if err := c.approval(description); err != nil {
		return err
	}
	p, err := a.change(description, func() error { out, e := a.run("ufw", args...); fmt.Print(out); return e })
	if err == nil {
		a.showPending(p)
	}
	return err
}
func (a *app) addRule(c *console, edit bool) error {
	var number string
	var selected string
	if edit {
		out, err := a.run("ufw", "status", "numbered")
		if err != nil {
			return err
		}
		fmt.Print(out)
		number, err = c.ask("Номер изменяемой строки (IPv4 и IPv6 — отдельные строки): ")
		if err != nil {
			return err
		}
		selected, err = numberedLine(out, number)
		if err != nil {
			return err
		}
	}
	action, err := c.ask("Действие [allow / deny / limit]: ")
	if err != nil {
		return err
	}
	proto, err := c.ask("Протокол [tcp / udp]: ")
	if err != nil {
		return err
	}
	port, err := c.ask("Порт или диапазон [например 443 / 8000:8010]: ")
	if err != nil {
		return err
	}
	source, err := c.ask("Источник [IP / подсеть / any; Enter = any]: ")
	if err != nil {
		return err
	}
	comment, err := c.ask("Комментарий: ")
	if err != nil {
		return err
	}
	r := rule{action, proto, port, source, comment}
	args, err := r.args()
	if err != nil {
		return err
	}
	if edit {
		if err = editFamily(selected, source); err != nil {
			return err
		}
	}
	desc := strings.Join(args, " ")
	if !edit {
		fmt.Println("Первое подходящее правило определяет результат: запрет в конце может не сработать после разрешения.")
		position, e := c.ask("Размещение [начало / конец; Enter = конец]: ")
		if e != nil {
			return e
		}
		if position == "начало" {
			args = append([]string{"prepend"}, args...)
		} else if position != "" && position != "конец" {
			return errors.New("размещение: начало или конец")
		}
		desc = strings.Join(args, " ")
		return a.applyUFW(c, desc, args...)
	}
	desc = "Заменить " + selected + " на " + desc
	if err = c.approval(desc); err != nil {
		return err
	}
	p, err := a.change(desc, func() error {
		out, e := a.run("ufw", "status", "numbered")
		if e != nil {
			return e
		}
		current, e := numberedLine(out, number)
		if e != nil {
			return e
		}
		if current != selected {
			return errors.New("список правил изменился; выберите правило заново")
		}
		if _, e = a.run("ufw", "--force", "delete", number); e != nil {
			return e
		}
		// Keep the replacement at the selected position; preserve rule precedence.
		insert := append([]string{"insert", number}, args...)
		out, e = a.run("ufw", insert...)
		fmt.Print(out)
		return e
	})
	if err == nil {
		a.showPending(p)
	}
	return err
}
func editFamily(selected, source string) error {
	ruleText := strings.SplitN(selected, "#", 2)[0]
	if strings.Contains(ruleText, " OUT") || strings.Contains(ruleText, " FWD") || strings.Contains(ruleText, " on ") {
		return errors.New("редактор поддерживает только обычные входящие правила без привязки к интерфейсу")
	}
	if source == "" || source == "any" {
		return errors.New("при изменении укажите семейство явно: 0.0.0.0/0 для всех IPv4 или ::/0 для всех IPv6; также можно конкретный IP/подсеть")
	}
	addr, e := netip.ParseAddr(source)
	if e != nil {
		p, err := netip.ParsePrefix(source)
		if err != nil {
			return err
		}
		addr = p.Addr()
	}
	// The (v6) marker is before the comment; a comment cannot affect this check.
	if strings.Contains(ruleText, "(v6)") != addr.Is6() {
		return errors.New("заменяемое правило и источник должны иметь одно семейство IP")
	}
	return nil
}
func numberedLine(out, number string) (string, error) {
	n, e := strconv.Atoi(number)
	if e != nil || n < 1 || strconv.Itoa(n) != number {
		return "", errors.New("неверный номер правила")
	}
	re := regexp.MustCompile(`^\[\s*` + strconv.Itoa(n) + `\]\s+`)
	for _, line := range strings.Split(out, "\n") {
		if re.MatchString(line) {
			return line, nil
		}
	}
	return "", errors.New("правило не найдено; UFW должен быть включён")
}
func (a *app) deleteRule(c *console) error {
	out, err := a.run("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	fmt.Print(out)
	n, err := c.ask("Номер удаляемой строки (IPv4 и IPv6 отдельно): ")
	if err != nil {
		return err
	}
	selected, err := numberedLine(out, n)
	if err != nil {
		return err
	}
	if err = c.approval("Удалить " + selected); err != nil {
		return err
	}
	p, err := a.change("Удалить "+selected, func() error {
		current, e := a.run("ufw", "status", "numbered")
		if e != nil {
			return e
		}
		line, e := numberedLine(current, n)
		if e != nil {
			return e
		}
		if line != selected {
			return errors.New("список правил изменился; выберите правило заново")
		}
		out, e = a.run("ufw", "--force", "delete", n)
		fmt.Print(out)
		return e
	})
	if err == nil {
		a.showPending(p)
	}
	return err
}
func (a *app) menu() error {
	c := &console{bufio.NewReader(os.Stdin)}
	for {
		fmt.Printf("\nVPSWall %s — UFW — %s\n", version, hostname())
		fmt.Println("1. Состояние и правила\n2. Добавить правило\n3. Изменить правило\n4. Удалить правило\n5. Разрешить HTTP/HTTPS\n6. Политика входящих соединений\n7. Включить / выключить UFW\n8. Слушающие порты\n9. Копии: создать / восстановить\n10. Журнал UFW\n11. История изменений\n12. Откат ожидающего изменения\n13. Подтвердить изменение (из нового SSH)\n0. Выход")
		choice, err := c.ask("Выбор: ")
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "0":
			return nil
		case "1":
			err = a.status()
		case "2":
			err = a.addRule(c, false)
		case "3":
			err = a.addRule(c, true)
		case "4":
			err = a.deleteRule(c)
		case "5":
			err = c.approval("Разрешить входящие TCP 80 и 443 для всех адресов")
			if err == nil {
				var p *pending
				p, err = a.change("HTTP/HTTPS", func() error {
					for _, port := range []string{"80", "443"} {
						args, _ := (rule{"allow", "tcp", port, "any", "Web"}).args()
						if _, e := a.run("ufw", args...); e != nil {
							return e
						}
					}
					return nil
				})
				if err == nil {
					a.showPending(p)
				}
			}
		case "6":
			var policy string
			policy, err = c.ask("Входящие [deny / reject / allow]: ")
			if err == nil {
				if policy != "deny" && policy != "reject" && policy != "allow" {
					err = errors.New("неверная политика")
				} else {
					err = a.applyUFW(c, "Политика входящих: "+policy, "default", policy, "incoming")
				}
			}
		case "7":
			var mode string
			mode, err = c.ask("[enable / disable]: ")
			if err == nil {
				if mode != "enable" && mode != "disable" {
					err = errors.New("неверное действие")
				} else {
					fmt.Println("Перед включением убедитесь, что разрешены реальный порт SSH и ваш источник. Новые правила при выключенном UFW сохраняются, но не фильтруют трафик.")
					err = a.applyUFW(c, "UFW "+mode, "--force", mode)
				}
			}
		case "8":
			var out string
			out, err = a.run("ss", "-lntup")
			fmt.Print(out)
		case "9":
			err = a.listBackups()
			if err != nil {
				break
			}
			var id string
			id, err = c.ask("Enter — создать копию; ID — восстановить: ")
			if err != nil {
				break
			}
			if id == "" {
				var unlock func()
				unlock, err = lockState(filepath.Join(a.state, "lock"))
				if err == nil {
					var s snapshot
					s, err = a.backup("Ручная копия")
					unlock()
					if err == nil {
						fmt.Println("Копия:", s.ID)
					}
				}
			} else {
				if _, err = a.loadSnapshot(id); err == nil {
					err = c.approval("Восстановить копию " + id)
					if err == nil {
						var p *pending
						p, err = a.change("Восстановление "+id, func() error { return a.restore(id) })
						if err == nil {
							a.showPending(p)
						}
					}
				}
			}
		case "10":
			var out string
			out, err = a.run("journalctl", "-k", "--grep=UFW", "-n", "80", "--no-pager")
			fmt.Print(out)
			fmt.Println("Если записей нет, проверьте журналирование UFW: sudo ufw logging low")
		case "11":
			var b []byte
			b, err = os.ReadFile(filepath.Join(a.state, "history.log"))
			if errors.Is(err, os.ErrNotExist) {
				err = nil
				fmt.Println("История пуста")
			}
			fmt.Print(string(b))
		case "12":
			var yes string
			yes, err = c.ask("Восстановить конфигурацию до ожидающего изменения? Введите да: ")
			if err == nil && yes == "да" {
				err = a.rollback()
			}
		case "13":
			var token string
			token, err = c.ask("Код подтверждения: ")
			if err == nil {
				err = a.confirm(token)
			}
		default:
			err = errors.New("нет такого пункта")
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			fmt.Println("Ошибка:", err)
		}
	}
}
func hostname() string {
	h, e := os.Hostname()
	if e != nil {
		return "VPS"
	}
	return h
}
func legacyMain() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("vpswall", version)
		return
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		fmt.Println("sudo vpswall — меню\nsudo vpswall status — правила\nsudo --preserve-env=SSH_CONNECTION vpswall confirm CODE — подтвердить из нового SSH\nsudo vpswall rollback — восстановить ожидающее изменение\nLinux + UFW + systemd; установка: sudo ./install.sh")
		return
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Для управления UFW требуется Linux.")
		os.Exit(1)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Запустите через sudo.")
		os.Exit(1)
	}
	a := &app{state: "/var/lib/vpswall", etc: "/etc", run: command, now: time.Now, ssh: os.Getenv("SSH_CONNECTION")}
	err := a.init()
	if err == nil {
		switch {
		case len(args) == 0:
			err = a.menu()
		case len(args) == 1 && args[0] == "status":
			err = a.status()
		case len(args) == 1 && args[0] == "rollback":
			err = a.rollback()
		case len(args) == 2 && args[0] == "confirm":
			err = a.confirm(args[1])
			if err == nil {
				fmt.Println("Изменения подтверждены.")
			}
		default:
			err = errors.New("неизвестная команда; vpswall --help")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}
