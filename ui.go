package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	accent        = lipgloss.Color("43")
	amber         = lipgloss.Color("221")
	muted         = lipgloss.Color("245")
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(accent)
	mutedStyle    = lipgloss.NewStyle().Foreground(muted)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("235")).Background(accent).Bold(true).Padding(0, 1)
	panelStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("239")).Padding(1, 2)
)

type uiItem struct{ title, description, key, id string }
type uiField struct {
	label   string
	input   textinput.Model
	choices []string
}
type operationDone struct {
	text, next string
	err        error
}
type uiTick time.Time
type uiModel struct {
	m                                   *manager
	config                              managerConfig
	windows                             []window
	pending                             *managerChange
	screen                              string
	items                               []uiItem
	cursor                              int
	width, height                       int
	fields                              []uiField
	formKind, formID                    string
	focus                               int
	reviewTitle, reviewText, reviewNext string
	reviewAction                        func() (string, error)
	busy                                bool
	busyTitle                           string
	spin                                spinner.Model
	output                              viewport.Model
	errorText                           string
}

func newUI(m *manager) uiModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = titleStyle
	u := uiModel{m: m, screen: "home", width: 100, height: 32, spin: s, output: viewport.New(80, 18)}
	u.reload()
	if u.config.Backend == "" {
		u.screen = "backend"
	}
	u.populate()
	return u
}
func tickUI() tea.Cmd           { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return uiTick(t) }) }
func (u uiModel) Init() tea.Cmd { return tea.Batch(u.spin.Tick, tickUI()) }
func (u *uiModel) reload() {
	var e error
	u.config, e = u.m.config()
	if e != nil {
		u.errorText = e.Error()
	}
	u.windows, e = u.m.windows()
	if e != nil {
		u.errorText = e.Error()
	}
	u.pending, e = u.m.pending()
	if e != nil {
		u.errorText = e.Error()
	}
}
func (u *uiModel) open(screen string) {
	u.screen = screen
	u.cursor = 0
	u.errorText = ""
	u.reload()
	u.populate()
}
func (u *uiModel) populate() {
	u.items = nil
	switch u.screen {
	case "home":
		u.items = []uiItem{
			{"Правила", "Разрешения, запреты, приоритет и источники доступа", "rules", ""},
			{"Время и окна портов", "Открыть на час, в заданную дату или каждый день", "windows", ""},
			{"Сертификаты · Certbot", "Порт 80 только на время попытки продления", "certbot", ""},
			{"Сетевой экран", "Выбор инструмента, установка и состояние", "backend", ""},
			{"Политика и включение", "Разрешить или запретить прочий входящий трафик", "settings", ""},
			{"Диагностика", "Все правила, слушающие порты и журнал", "diagnostics", ""},
			{"Копии и история", "Сохранить или восстановить правила VPSWall", "history", ""},
		}
	case "backend":
		for _, b := range []string{"ufw", "firewalld", "nftables", "iptables"} {
			descs := map[string]string{"ufw": "Простой firewall для Ubuntu/Debian", "firewalld": "Зоны, службы и rich rules", "nftables": "Современные таблицы и атомарное применение", "iptables": "Совместимость с существующими Linux-системами"}
			label := strings.ToUpper(b)
			if b == u.config.Backend {
				label += " · выбран"
			}
			u.items = append(u.items, uiItem{label, descs[b], "select", b})
		}
		u.items = append(u.items, uiItem{"Зона firewalld", "По умолчанию public; выбирайте зону своего интерфейса", "zone", ""})
	case "rules":
		u.items = append(u.items, uiItem{"＋ Добавить правило", "Разрешить / запретить / отклонить TCP или UDP", "add", ""})
		for _, r := range sortedRules(u.config.Rules) {
			title := fmt.Sprintf("%s  %s/%s  ← %s", actionLabel(r.Action), r.Port, r.Protocol, r.Source)
			u.items = append(u.items, uiItem{title, fmt.Sprintf("приоритет %d · %s", r.Priority, r.Comment), "rule", r.ID})
		}
		u.items = append(u.items, uiItem{"Все правила системы", "Существующие чужие правила доступны для просмотра", "raw", ""})
	case "rule":
		for _, r := range u.config.Rules {
			if r.ID == u.formID {
				u.items = []uiItem{{"Изменить", r.Port + "/" + r.Protocol + " · " + r.Source, "edit", r.ID}, {"Удалить", "Удаляется только выбранное правило VPSWall", "delete", r.ID}}
			}
		}
	case "windows":
		u.items = []uiItem{{"Открыть сейчас", "Временное разрешение с автоматическим закрытием", "window-new", "lease"}, {"Одноразовое окно", "Дата, время, часовой пояс и длительность", "window-new", "once"}, {"Ежедневное окно", "Например 03:00–04:00 по Москве", "window-new", "daily"}}
		for _, w := range u.windows {
			status := "ожидает"
			if _, _, active := w.interval(u.m.now()); active {
				status = "ОТКРЫТ"
			} else if w.Kind != "daily" && !u.m.now().Before(w.Start.Add(time.Duration(w.Seconds)*time.Second)) {
				status = "завершён"
			}
			if w.Paused {
				status = "пауза"
			}
			when := w.Start.Format("02.01 15:04 MST")
			if w.Kind == "daily" {
				when = w.Clock + " · " + w.Zone
			}
			u.items = append(u.items, uiItem{fmt.Sprintf("%s/%s · %s", w.Rule.Port, w.Rule.Protocol, status), when + " · " + time.Duration(w.Seconds*int64(time.Second)).String(), "window", w.ID})
		}
	case "window":
		u.items = []uiItem{{"Пауза / возобновить", "Пауза удаляет только разрешение этого окна", "pause-window", u.formID}, {"Удалить окно", "Чужие и постоянные разрешения порта сохраняются", "delete-window", u.formID}}
	case "certbot":
		u.items = []uiItem{{"Подключить хуки", "Открывать 80 перед продлением; закрывать после попытки", "certbot-hooks", ""}, {"Задать время обновления", "Свой ежедневный timer Certbot; замена стандартного timer", "certbot-time", ""}, {"Проверить продление", "certbot renew --dry-run с тестовым центром сертификации", "certbot-test", ""}, {"Состояние таймера", "Расписание и результат последней попытки", "certbot-status", ""}, {"Отключить интеграцию", "Удалить свои хуки и вернуть стандартные timers", "certbot-remove", ""}}
	case "settings":
		label := "Включить"
		if u.config.Enabled {
			label = "Выключить"
		}
		u.items = []uiItem{{label + " выбранный экран", "При включении добавляется разрешение текущего SSH", "toggle", ""}, {"Запретить прочий входящий трафик", "Сохранить существующие разрешения и правила VPSWall", "policy", "deny"}, {"Разрешить прочий входящий трафик", "Для nftables/iptables: возврат к базовой политике системы", "policy", "allow"}, {"Подтвердить изменение", "Из нового SSH-подключения с выданным кодом", "confirm", ""}, {"Отменить изменение", "Восстановить настройки VPSWall до изменения", "rollback", ""}}
	case "diagnostics":
		u.items = []uiItem{{"Все правила", "Конфигурация выбранного firewall", "raw", ""}, {"Слушающие порты", "Порты TCP/UDP и процессы — это не проверка извне", "ports", ""}, {"Журнал ядра", "Последние события сетевого экрана", "kernel-log", ""}, {"Планировщик", "Состояние worker, timers и ошибок", "worker-log", ""}}
	case "history":
		u.items = []uiItem{{"Сохранить копию", "Снимок настроек и правил VPSWall", "backup", ""}, {"История", "Изменения, окна портов и обновления сертификатов", "audit", ""}}
		entries, _ := os.ReadDir(u.m.path("managed-backups"))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				id := strings.TrimSuffix(e.Name(), ".json")
				if idPattern.MatchString(id) {
					u.items = append(u.items, uiItem{"Восстановить " + id, "Восстановление с таймером отката", "restore", id})
				}
			}
		}
	}
	if u.cursor >= len(u.items) {
		u.cursor = max(0, len(u.items)-1)
	}
}
func actionLabel(s string) string {
	return map[string]string{"allow": "РАЗРЕШИТЬ", "deny": "ЗАПРЕТИТЬ", "reject": "ОТКЛОНИТЬ"}[s]
}
func field(label, value string, choices ...string) uiField {
	t := textinput.New()
	t.SetValue(value)
	t.CharLimit = 120
	t.Prompt = ""
	t.Width = 44
	return uiField{label, t, choices}
}
func (u *uiModel) form(kind, id string, fields []uiField) {
	u.screen = "form"
	u.formKind = kind
	u.formID = id
	u.fields = fields
	u.focus = 0
	u.errorText = ""
	u.fields[0].input.Focus()
}
func (u *uiModel) ruleForm(id string) {
	r := managedRule{Action: "allow", Protocol: "tcp", Port: "443", Source: "any", Priority: 5000}
	for _, v := range u.config.Rules {
		if v.ID == id {
			r = v
		}
	}
	labels := map[string]string{"allow": "разрешить", "deny": "запретить", "reject": "отклонить"}
	u.form("rule", id, []uiField{field("Действие", labels[r.Action], "разрешить", "запретить", "отклонить"), field("Протокол", r.Protocol, "tcp", "udp"), field("Порт или диапазон", r.Port), field("Источник · IP / подсеть / any", r.Source), field("Приоритет · меньше — раньше", strconv.Itoa(r.Priority)), field("Название правила", r.Comment)})
}
func (u *uiModel) windowForm(kind string) {
	f := []uiField{field("Порт или диапазон", "80"), field("Протокол", "tcp", "tcp", "udp"), field("Источник · IP / подсеть / any", "any"), field("Длительность · 30m / 1h / 2h", "1h")}
	if kind == "daily" {
		f = append(f, field("Каждый день в · ЧЧ:ММ", "03:00"), field("Часовой пояс IANA", "Europe/Moscow"))
	}
	if kind == "once" {
		f = append(f, field("Начало · ГГГГ-ММ-ДД ЧЧ:ММ", u.m.now().In(moscow()).Add(time.Hour).Format("2006-01-02 15:04")), field("Часовой пояс IANA", "Europe/Moscow"))
	}
	u.form("window-"+kind, "", f)
}
func moscow() *time.Location { loc, _ := time.LoadLocation("Europe/Moscow"); return loc }
func (u *uiModel) review(title, text, next string, action func() (string, error)) {
	u.screen = "review"
	u.reviewTitle = title
	u.reviewText = text
	u.reviewNext = next
	u.reviewAction = action
	u.cursor = 1
	u.errorText = ""
	u.output.Width = max(20, min(u.width-14, 106))
	u.output.Height = max(3, u.height-19)
	u.output.SetContent(ansi.Wrap(text, u.output.Width, " "))
	u.output.GotoTop()
}
func (u *uiModel) operation(title, next string, fn func() (string, error)) tea.Cmd {
	u.busy = true
	u.busyTitle = title
	return func() tea.Msg { text, e := fn(); return operationDone{text, next, e} }
}
func changeMessage(p *managerChange) string {
	if p == nil {
		return "Изменение отменено по таймеру."
	}
	return fmt.Sprintf("Изменение применено временно.\n\nПроверьте доступ из НОВОГО SSH-подключения и подтвердите:\n\nsudo --preserve-env=SSH_CONNECTION vpswall confirm %s\n\nОткат через 120 секунд с начала изменения.\nВыход из панели не отменяет таймер.", p.Token)
}
func (u *uiModel) configReview(description string, c managerConfig) {
	m := u.m
	u.review("Применить изменение?", description+"\n\nБудет запущен независимый таймер отката на 120 секунд.", "home", func() (string, error) { p, e := m.change(description, c); return changeMessage(p), e })
}
func (u *uiModel) submitForm() error {
	values := []string{}
	for _, f := range u.fields {
		values = append(values, strings.TrimSpace(f.input.Value()))
	}
	m := u.m
	switch u.formKind {
	case "rule":
		action := map[string]string{"разрешить": "allow", "запретить": "deny", "отклонить": "reject"}[values[0]]
		r, e := newManaged(action, values[1], values[2], values[3], values[5])
		if e != nil {
			return e
		}
		r.Priority, e = strconv.Atoi(values[4])
		if e != nil {
			return e
		}
		if e = r.validate(); e != nil {
			return e
		}
		c := u.config
		c.Rules = append([]managedRule{}, c.Rules...)
		replaced := false
		for i, old := range c.Rules {
			if old.ID == u.formID {
				c.Rules[i] = r
				replaced = true
			}
		}
		if !replaced {
			for _, old := range c.Rules {
				if old.Action == r.Action && old.Port == r.Port && old.Protocol == r.Protocol && old.Source == r.Source {
					return errorsNew("такое правило VPSWall уже существует")
				}
			}
			c.Rules = append(c.Rules, r)
		}
		u.configReview(fmt.Sprintf("%s %s/%s от %s · приоритет %d", actionLabel(r.Action), r.Port, r.Protocol, r.Source, r.Priority), c)
	case "window-lease", "window-once", "window-daily":
		duration, e := time.ParseDuration(values[3])
		if e != nil {
			return errorsNew("длительность: например 30m или 1h")
		}
		r, e := newManaged("allow", values[1], values[0], values[2], "Временное окно")
		if e != nil {
			return e
		}
		kind := strings.TrimPrefix(u.formKind, "window-")
		w := window{ID: r.ID, Rule: r, Kind: kind, Seconds: int64(duration / time.Second), Start: m.now()}
		if kind == "daily" {
			w.Clock = values[4]
			w.Zone = values[5]
		}
		if kind == "once" {
			loc, e := time.LoadLocation(values[5])
			if e != nil {
				return e
			}
			w.Start, e = time.ParseInLocation("2006-01-02 15:04", values[4], loc)
			if e != nil {
				return e
			}
			if !w.Start.After(m.now()) {
				return errorsNew("начало должно быть в будущем")
			}
			w.Zone = values[5]
		}
		if e = w.validate(); e != nil {
			return e
		}
		when := "сейчас"
		if kind == "daily" {
			when = "ежедневно в " + w.Clock + " " + w.Zone
		}
		if kind == "once" {
			when = w.Start.Format("2006-01-02 15:04 MST")
		}
		u.review("Создать окно?", fmt.Sprintf("Открыть %s/%s от %s\nНачало: %s\nДлительность: %s\n\nУдаляется только временное разрешение VPSWall.\nПостоянные и чужие разрешения этого порта сохраняются.\nПланировщик работает без открытой панели; точность — до 15 секунд.", r.Port, r.Protocol, r.Source, when, duration), "windows", func() (string, error) {
			e := m.saveWindow(w)
			return "Окно сохранено.\n\nFirewall не запускает слушающий сервис: его нужно настроить отдельно.", e
		})
	case "certbot-time":
		clock, zone := values[0], values[1]
		if _, _, e := clockParts(clock); e != nil {
			return e
		}
		if _, e := time.LoadLocation(zone); e != nil {
			return e
		}
		u.review("Настроить обновление Certbot?", "Ежедневно в "+clock+" "+zone+"\n\nБудут установлены pre/post хуки, настроен новый timer\nи отключены стандартные timers Certbot, если они включены.\nПорт 80 открывается только при попытке продления, максимум на час.\nНастройки сертификатов и веб-сервера сохраняются.", "certbot", func() (string, error) {
			return "Расписание Certbot установлено.", m.certbotTimer(clock, zone)
		})
	case "zone":
		zone := values[0]
		u.review("Сменить зону firewalld?", "Выбранная зона: "+zone+"\nУбедитесь, что ваш интерфейс или источник относятся к этой зоне.", "backend", func() (string, error) { return "Зона сохранена.", m.selectBackend("firewalld", zone) })
	case "confirm":
		token := values[0]
		u.review("Подтвердить правила?", "Код: "+token+"\nПодтверждение доступно из нового SSH-подключения.", "home", func() (string, error) { return "Изменение подтверждено.", m.confirm(token) })
	}
	return nil
}
func errorsNew(s string) error { return fmt.Errorf("%s", s) }
func (u *uiModel) activate() tea.Cmd {
	if len(u.items) == 0 {
		return nil
	}
	item := u.items[u.cursor]
	m := u.m
	switch item.key {
	case "rules", "windows", "certbot", "backend", "settings", "diagnostics", "history":
		u.open(item.key)
	case "select":
		b := item.id
		zone := "public"
		if b == "firewalld" && u.config.Zone != "" {
			zone = u.config.Zone
		}
		u.review("Выбрать "+strings.ToUpper(b)+"?", "Если инструмент отсутствует, VPSWall установит пакет через apt/dnf.\nДругой активный firewall автоматически не отключается.\nУстановка не включает фильтрацию; включение — отдельный шаг.\nЧужие правила не мигрируют и не удаляются.", "home", func() (string, error) {
			return "Выбран " + strings.ToUpper(b) + ".\nОткройте «Политика и включение», если firewall ещё не активен.", m.selectBackend(b, zone)
		})
	case "zone":
		u.form("zone", "", []uiField{field("Зона firewalld", u.config.Zone)})
	case "add":
		u.ruleForm("")
	case "rule":
		u.formID = item.id
		u.open("rule")
	case "edit":
		u.ruleForm(item.id)
	case "delete":
		c := u.config
		c.Rules = nil
		for _, r := range u.config.Rules {
			if r.ID != item.id {
				c.Rules = append(c.Rules, r)
			}
		}
		u.configReview("Удалить правило "+item.id, c)
	case "window-new":
		u.windowForm(item.id)
	case "window":
		u.formID = item.id
		u.open("window")
	case "pause-window":
		id := item.id
		u.review("Изменить состояние окна?", "Пауза закрывает только его временное разрешение.", "windows", func() (string, error) { return "Состояние окна изменено.", m.pauseWindow(id) })
	case "delete-window":
		id := item.id
		u.review("Удалить окно?", "Временное разрешение будет снято; постоянные правила сохраняются.", "windows", func() (string, error) { return "Окно удалено.", m.removeWindow(id) })
	case "raw":
		c := u.config
		return u.operation("Читаю правила", u.screen, func() (string, error) { return m.rawStatus(c) })
	case "toggle":
		c := u.config
		c.Rules = append([]managedRule{}, c.Rules...)
		c.Enabled = !c.Enabled
		if c.Enabled {
			r, e := sshRule(m.ssh)
			if e != nil {
				u.errorText = e.Error()
				return nil
			}
			r.Priority = 0
			present := false
			for _, old := range c.Rules {
				if old.Action == r.Action && old.Port == r.Port && old.Protocol == r.Protocol && old.Source == r.Source {
					present = true
				}
			}
			if !present {
				c.Rules = append(c.Rules, r)
			}
		}
		text := "Выключить выбранный экран"
		if c.Enabled {
			text = "Включить выбранный экран и сохранить доступ из текущего SSH"
		}
		u.configReview(text, c)
	case "policy":
		c := u.config
		c.Policy = item.id
		u.configReview("Политика прочего входящего трафика: "+item.id, c)
	case "confirm":
		token := ""
		if u.pending != nil {
			token = u.pending.Token
		}
		u.form("confirm", "", []uiField{field("Код подтверждения", token)})
	case "rollback":
		u.review("Отменить изменение?", "Восстановить правила и настройки VPSWall до последнего изменения.", "home", func() (string, error) { return "Откат выполнен.", m.rollback() })
	case "certbot-hooks":
		u.review("Подключить Certbot?", "Pre-hook разрешит TCP 80 для HTTP-01.\nPost-hook снимет разрешение после попытки продления.\nАварийный срок открытия — один час.\nСуществующие хуки и сертификаты сохраняются.", "certbot", func() (string, error) {
			return "Хуки установлены.\nВыполните проверку продления перед первым рабочим запуском.", m.installCertbotHooks()
		})
	case "certbot-time":
		u.form("certbot-time", "", []uiField{field("Ежедневно в · ЧЧ:ММ", "03:00"), field("Часовой пояс IANA", "Europe/Moscow")})
	case "certbot-test":
		u.review("Проверить продление?", "Certbot renew --dry-run\nИспользуется тестовый CA; хуки открытия и закрытия порта выполняются.\nСервис на порту 80 обеспечивается вашим текущим способом проверки.", "certbot", func() (string, error) { return m.run("certbot", "renew", "--dry-run") })
	case "certbot-status":
		return u.operation("Читаю расписание", "certbot", func() (string, error) {
			return m.run("systemctl", "status", "vpswall-certbot.timer", "vpswall-certbot.service", "--no-pager")
		})
	case "certbot-remove":
		u.review("Отключить интеграцию?", "Удалить только хуки и timer VPSWall, закрыть его окно\nи вернуть ранее включённые стандартные timers Certbot.", "certbot", func() (string, error) {
			return "Интеграция отключена.", m.removeCertbotIntegration()
		})
	case "ports":
		return u.operation("Читаю порты", "diagnostics", func() (string, error) { return m.run("ss", "-lntup") })
	case "kernel-log":
		return u.operation("Читаю журнал", "diagnostics", func() (string, error) { return m.run("journalctl", "-k", "-n", "100", "--no-pager") })
	case "worker-log":
		return u.operation("Читаю планировщик", "diagnostics", func() (string, error) {
			return m.run("journalctl", "-u", "vpswall-worker.service", "-u", "vpswall-recover.service", "-n", "80", "--no-pager")
		})
	case "audit":
		return u.operation("Читаю историю", "history", func() (string, error) { b, e := os.ReadFile(m.path("history.log")); return string(b), e })
	case "backup":
		return u.operation("Создаю копию", "history", func() (string, error) { id, e := m.saveBackup(); return "Копия сохранена: " + id, e })
	case "restore":
		id := item.id
		var c managerConfig
		if e := readJSON(m.path("managed-backups/"+id+".json"), &c); e != nil {
			u.errorText = e.Error()
			return nil
		}
		u.configReview("Восстановить копию "+id, c)
	}
	return nil
}
func (u uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		u.width = v.Width
		u.height = v.Height
		u.output.Width = max(20, min(v.Width-14, 106))
		u.output.Height = max(5, v.Height-15)
		if u.screen == "review" {
			u.output.Height = max(3, v.Height-19)
		}
		return u, nil
	case uiTick:
		u.reload()
		return u, tickUI()
	case operationDone:
		u.busy = false
		u.reload()
		text := v.text
		if v.err != nil {
			text = "Ошибка: " + v.err.Error() + "\n\n" + text
		}
		u.reviewNext = v.next
		u.output.Height = max(5, u.height-15)
		u.output.SetContent(ansi.Wrap(cleanOutput(text), u.output.Width, " "))
		u.output.GotoTop()
		u.screen = "output"
		return u, nil
	case tea.KeyMsg:
		key := v.String()
		if key == "ctrl+c" {
			return u, tea.Quit
		}
		if u.busy {
			return u, nil
		}
		if u.screen == "output" {
			if key == "esc" || key == "enter" {
				u.open(u.reviewNext)
				return u, nil
			}
			var cmd tea.Cmd
			u.output, cmd = u.output.Update(msg)
			return u, cmd
		}
		if u.screen == "form" {
			if key == "esc" {
				u.open("home")
				return u, nil
			}
			if key == "tab" || key == "down" || key == "enter" {
				if key == "enter" && u.focus == len(u.fields) {
					if e := u.submitForm(); e != nil {
						u.errorText = e.Error()
					}
					return u, nil
				}
				u.focus = (u.focus + 1) % (len(u.fields) + 1)
			} else if key == "shift+tab" || key == "up" {
				u.focus = (u.focus + len(u.fields)) % (len(u.fields) + 1)
			} else if u.focus < len(u.fields) {
				f := &u.fields[u.focus]
				if len(f.choices) > 0 && (key == "left" || key == "right") {
					i := 0
					for j, c := range f.choices {
						if c == f.input.Value() {
							i = j
						}
					}
					if key == "right" {
						i = (i + 1) % len(f.choices)
					} else {
						i = (i + len(f.choices) - 1) % len(f.choices)
					}
					f.input.SetValue(f.choices[i])
				} else {
					var cmd tea.Cmd
					f.input, cmd = f.input.Update(msg)
					return u, cmd
				}
			}
			for i := range u.fields {
				if i == u.focus {
					u.fields[i].input.Focus()
				} else {
					u.fields[i].input.Blur()
				}
			}
			return u, nil
		}
		if u.screen == "review" {
			if key == "up" || key == "down" || key == "pgup" || key == "pgdown" {
				var cmd tea.Cmd
				u.output, cmd = u.output.Update(msg)
				return u, cmd
			}
			switch key {
			case "esc":
				u.open("home")
			case "left", "right", "tab":
				u.cursor = 1 - u.cursor
			case "enter":
				if u.cursor == 0 {
					return u, u.operation(u.reviewTitle, u.reviewNext, u.reviewAction)
				}
				u.open("home")
			}
			return u, nil
		}
		switch key {
		case "q":
			return u, tea.Quit
		case "esc", "backspace":
			u.open("home")
		case "up", "k":
			u.cursor = max(0, u.cursor-1)
		case "down", "j":
			u.cursor = min(len(u.items)-1, u.cursor+1)
		case "home":
			u.cursor = 0
		case "end":
			u.cursor = max(0, len(u.items)-1)
		case "enter":
			cmd := u.activate()
			return u, cmd
		case "a":
			if u.screen == "rules" {
				u.ruleForm("")
			}
		case "r":
			u.reload()
			u.populate()
		}
		return u, nil
	}
	var cmd tea.Cmd
	u.spin, cmd = u.spin.Update(msg)
	return u, cmd
}
func cleanOutput(s string) string {
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		if r == 127 {
			return -1
		}
		return r
	}, s)
}
func screenTitle(s string) string {
	switch s {
	case "home":
		return "Панель управления"
	case "rules", "rule":
		return "Правила доступа"
	case "windows", "window":
		return "Время и окна портов"
	case "certbot":
		return "Сертификаты · Certbot"
	case "backend":
		return "Выбор сетевого экрана"
	case "settings":
		return "Политика и включение"
	case "diagnostics":
		return "Диагностика"
	case "history":
		return "Копии и история"
	case "form":
		return "Настройка"
	case "review":
		return "Проверка изменения"
	default:
		return "Результат"
	}
}
func (u uiModel) View() string {
	width := min(u.width-4, 120)
	if width < 45 || u.height < 24 {
		return "VPSWall: увеличьте терминал хотя бы до 49×24.\nCtrl+C — выход"
	}
	header := titleStyle.Render("VPSWALL") + mutedStyle.Render("  /  "+hostname()+"  /  v"+version)
	if u.m.demo {
		header += "  " + lipgloss.NewStyle().Foreground(amber).Render("ДЕМО")
	}
	summary := u.m.summary()
	body := ""
	hint := "↑↓ выбор · Enter открыть · Esc домой · R обновить · Q выход"
	if u.busy {
		body = u.spin.View() + "  " + u.busyTitle + "\n\nПожалуйста, дождитесь завершения операции."
		hint = "Ctrl+C — выход из панели; фоновые таймеры продолжают работать"
	} else {
		switch u.screen {
		case "form":
			for i, f := range u.fields {
				labelWidth := min(34, (width-10)/2)
				labelText := ansi.Truncate(f.label, labelWidth-1, "…")
				label := mutedStyle.Width(labelWidth).Render(labelText)
				f.input.Width = max(10, width-12-labelWidth)
				value := f.input.View()
				if len(f.choices) > 0 {
					value = "‹ " + f.input.Value() + " ›"
				}
				if i == u.focus {
					label = titleStyle.Width(labelWidth).Render(labelText)
					value = lipgloss.NewStyle().Foreground(amber).Render(value)
				}
				body += label + "  " + value + "\n"
			}
			submit := "  Проверить и продолжить  "
			if u.focus == len(u.fields) {
				submit = selectedStyle.Render(submit)
			}
			body += "\n" + submit
			hint = "Tab / ↑↓ поля · ←→ варианты · Enter далее · Esc отмена"
		case "review":
			body = titleStyle.Render(u.reviewTitle) + "\n\n" + u.output.View() + "\n\n"
			yes, no := "  Применить  ", "  Отмена  "
			if u.cursor == 0 {
				yes = selectedStyle.Render(yes)
			} else {
				no = selectedStyle.Render(no)
			}
			body += yes + "    " + no
			hint = "↑↓ детали · ←→ выбор · Enter подтвердить · Esc отмена"
		case "output":
			body = u.output.View()
			hint = "↑↓ / PgUp PgDn прокрутка · Enter / Esc назад"
		default:
			available := max(2, (u.height-13)/3)
			if u.pending != nil {
				available = max(2, (u.height-16)/3)
			}
			start := 0
			if u.cursor >= available {
				start = u.cursor - available + 1
			}
			end := min(len(u.items), start+available)
			for i := start; i < end; i++ {
				item := u.items[i]
				line := "  " + item.title
				if i == u.cursor {
					line = selectedStyle.Width(width - 10).Render("› " + item.title)
				}
				body += line + "\n" + mutedStyle.Render("  "+ansi.Truncate(item.description, width-12, "…")) + "\n\n"
			}
			if end < len(u.items) {
				body += mutedStyle.Render(fmt.Sprintf("↓ ещё %d пунктов", len(u.items)-end))
			}
		}
	}
	if u.errorText != "" {
		body += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(ansi.Wrap(u.errorText, width-10, " "))
	}
	if u.pending != nil {
		remaining := int(u.pending.Deadline.Sub(u.m.now()).Seconds())
		if remaining < 0 {
			remaining = 0
		}
		summary += "\n" + lipgloss.NewStyle().Foreground(amber).Render(fmt.Sprintf("ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ · %d сек · код %s", remaining, u.pending.Token))
	}
	box := panelStyle.Width(width - 6).Render(titleStyle.Render(screenTitle(u.screen)) + "\n\n" + body)
	return lipgloss.NewStyle().Padding(1, 2).Render(header + "\n" + mutedStyle.Render(summary) + "\n\n" + box + "\n" + mutedStyle.Render(hint))
}
