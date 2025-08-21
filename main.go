package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --go-package main bpf exec_tracker.c -- -I/usr/include/bpf

// ---------- Theme ----------
var (
	cFg     = lipgloss.Color("#E6E6E6")
	cMuted  = lipgloss.Color("#9AA4AF")
	cAccent = lipgloss.Color("#7C6DF8")
	cWarn   = lipgloss.Color("#FFD166")
	cDanger = lipgloss.Color("#FF5D5D")
	cOk     = lipgloss.Color("#44D18D")
	cBorder = lipgloss.Color("#2B2F36")

	appPad    = lipgloss.NewStyle().MarginTop(1).MarginBottom(1)
	titlePill = lipgloss.NewStyle().
			Background(cAccent).Foreground(lipgloss.Color("#0B0C0F")).
			Bold(true).Padding(0, 1)

	dim    = lipgloss.NewStyle().Foreground(cMuted)
	okText = lipgloss.NewStyle().Foreground(cOk).Bold(true)
	warn   = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	danger = lipgloss.NewStyle().Foreground(cDanger).Bold(true)

	headerPanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBorder).
			Padding(0, 1)
)

// ---------- Views / State ----------
type viewState int

const (
	listView viewState = iota
	detailsView
	treeView
)

type processNode struct {
	PID      int
	PPID     int
	Comm     string
	Children []*processNode
}

type processItem struct {
	PID  uint32
	Comm string
	Time time.Time
}

func (i processItem) FilterValue() string { return i.Comm }
func (i processItem) Title() string       { return fmt.Sprintf("%-10d %s", i.PID, i.Comm) }
func (i processItem) Description() string { return i.Time.Format("15:04:05.000") }

type newProcessMsg struct{ PID uint32; Comm string; Time time.Time }
type tickMsg struct{}
type treeMsg []*processNode

type processDetails struct {
	PID, PPID, User, Cmdline, Environ, Status string
}

// ---------- Helpers ----------
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
func gracefulKill(pid int, timeout time.Duration) {
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
func currentRate(hist []int) int {
	if len(hist) == 0 {
		return 0
	}
	return hist[len(hist)-1] * 2
}

// ---------- Keymap / Help ----------
type keyMap struct {
	ToggleView key.Binding
	Select     key.Binding
	Back       key.Binding
	BackCustom key.Binding
	Kill       key.Binding
	Quit       key.Binding
	Up         key.Binding
	Down       key.Binding
	Search     key.Binding
	Help       key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Search, k.Select, k.ToggleView, k.Kill, k.BackCustom, k.Quit, k.Help}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Search},
		{k.Select, k.ToggleView, k.BackCustom},
		{k.Kill, k.Quit, k.Help},
	}
}

var defaultKeys = keyMap{
	ToggleView: key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "tree/list")),
	Select:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "details")),
	Back:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back"), key.WithDisabled()),
	BackCustom: key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "back")),
	Kill:       key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "kill")),
	Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Up:         key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:       key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Search:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
}

// ---------- Model ----------
type model struct {
	state        viewState
	spinner      spinner.Model
	list         list.Model
	viewport     viewport.Model
	help         help.Model
	keys         keyMap
	tree         []*processNode
	details      processDetails
	history      []int
	processCount int
	width        int
	height       int

	confirmingKill bool
	confirmPid     int
	confirmText    string
}

func initialModel() model {
	s := spinner.New(
		spinner.WithSpinner(spinner.MiniDot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(cAccent)),
	)

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	delegate.Styles.SelectedDesc = lipgloss.NewStyle().Foreground(cAccent)

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.Title = "Recent Processes"
	l.SetShowStatusBar(true)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = titlePill
	l.Styles.StatusBar = dim
	l.Styles.FilterPrompt = dim
	l.Styles.FilterCursor = lipgloss.NewStyle().Foreground(cAccent)

	h := help.New()
	h.ShowAll = false

	return model{
		state:   listView,
		spinner: s,
		list:    l,
		help:    h,
		keys:    defaultKeys,
		history: make([]int, 80),
	}
}

func (m model) Init() tea.Cmd { return tea.Batch(m.spinner.Tick, tick(), buildTreeCmd()) }

func (m *model) setViewState(s viewState) {
	m.state = s
	m.keys.ToggleView.SetEnabled(s != detailsView)
	m.keys.Select.SetEnabled(s == listView)
	m.keys.Kill.SetEnabled(s == listView)
	m.keys.Back.SetEnabled(s == detailsView || s == treeView)
	m.keys.BackCustom.SetEnabled(s == detailsView || s == treeView)
	m.list.SetFilteringEnabled(s == listView)
}

// ---------- Update ----------
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width

		header := buildHeader(m.spinner.View(), currentRate(m.history), m.width)
		chart := buildChart(m.history)
		helpV := m.help.View(m.keys)

		headerH := lipgloss.Height(header)
		chartH := lipgloss.Height(chart)
		helpH := lipgloss.Height(helpV)

		outerMargin := 2
		gaps := 2

		availH := m.height - outerMargin - headerH - chartH - helpH - gaps
		availW := m.width

		availH = clamp(availH, 6, m.height)
		availW = clamp(availW, 20, m.width)

		m.list.SetSize(availW, availH)
		m.viewport = viewport.New(availW, availH)
		m.viewport.SetContent(renderTree(m.tree))
		return m, nil

	case treeMsg:
		m.tree = msg
		m.viewport.SetContent(renderTree(m.tree))
		return m, nil

	case newProcessMsg:
		item := processItem{PID: msg.PID, Comm: msg.Comm, Time: msg.Time}
		cmds = append(cmds, m.list.InsertItem(len(m.list.Items()), item))
		if len(m.list.Items()) > 500 {
			m.list.RemoveItem(0)
		}
		m.processCount++

	case tickMsg:
		m.history = append(m.history[1:], m.processCount)
		m.processCount = 0
		cmds = append(cmds, tick())

	case tea.KeyMsg:
		if m.confirmingKill {
			switch msg.String() {
			case "y", "Y":
				go gracefulKill(m.confirmPid, 1500*time.Millisecond)
				if m.list.Index() >= 0 && m.list.Index() < len(m.list.Items()) {
					m.list.RemoveItem(m.list.Index())
				}
				m.confirmingKill = false
				return m, nil
			case "n", "N", "esc":
				m.confirmingKill = false
				return m, nil
			default:
				return m, nil
			}
		}

		if key.Matches(msg, m.keys.Help) {
			m.help.ShowAll = !m.help.ShowAll
			return m, nil
		}

		switch m.state {
		case detailsView, treeView:
			if key.Matches(msg, m.keys.BackCustom) {
				m.setViewState(listView)
				return m, nil
			}
			if key.Matches(msg, m.keys.Back) {
				m.setViewState(listView)
				return m, nil
			}
			if key.Matches(msg, m.keys.Quit) {
				return m, tea.Quit
			}
			if m.state == treeView && key.Matches(msg, m.keys.ToggleView) {
				m.setViewState(listView)
				return m, nil
			}

		case listView:
			if m.list.FilterState() != list.Filtering {
				switch {
				case key.Matches(msg, m.keys.Quit):
					return m, tea.Quit
				case key.Matches(msg, m.keys.ToggleView):
					m.setViewState(treeView)
					cmds = append(cmds, buildTreeCmd())
				case key.Matches(msg, m.keys.Select):
					if item, ok := m.list.SelectedItem().(processItem); ok {
						m.details = getProcessDetails(item.PID)
						m.setViewState(detailsView)
					}
				case key.Matches(msg, m.keys.Kill):
					if item, ok := m.list.SelectedItem().(processItem); ok {
						m.confirmingKill = true
						m.confirmPid = int(item.PID)
						m.confirmText = fmt.Sprintf("Kill PID %d (%s)?", item.PID, item.Comm)
						return m, nil
					}
				}
			}
		}
	}

	m.spinner, cmd = m.spinner.Update(msg)
	cmds = append(cmds, cmd)

	if m.state == listView {
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.state == treeView {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// ---------- Views ----------
func (m model) View() string {
	switch m.state {
	case detailsView:
		return m.detailsView()
	case treeView:
		return m.treeView()
	default:
		return m.listView()
	}
}

func (m model) listView() string {
	header := buildHeader(m.spinner.View(), currentRate(m.history), m.width)
	chart := buildChart(m.history)

	main := lipgloss.JoinVertical(lipgloss.Left, header, chart, m.list.View())
	helpView := m.help.View(m.keys)

	screen := appPad.Render(lipgloss.JoinVertical(lipgloss.Left, main, helpView))

	if m.confirmingKill {
		dlg := modal(m.width, m.height, m.confirmText+"\n\n"+dim.Render("y confirm • n cancel"))
		return dlg
	}
	return screen
}

func (m model) detailsView() string {
	keyStyle := lipgloss.NewStyle().Foreground(cMuted).Width(14)
	valStyle := lipgloss.NewStyle().Foreground(cFg)
	line := func(k, v string) string {
		return lipgloss.JoinHorizontal(lipgloss.Left, keyStyle.Render(k), valStyle.Render(v))
	}
	body := lipgloss.JoinVertical(lipgloss.Left,
		line("PID:", m.details.PID),
		line("PPID:", m.details.PPID),
		line("User:", m.details.User),
		line("Status:", m.details.Status),
		line("Cmd:", m.details.Cmdline),
	)
	header := titlePill.Render("Process Details")
	return appPad.Render(lipgloss.JoinVertical(lipgloss.Left, header, body, m.help.View(m.keys)))
}

func (m model) treeView() string {
	header := buildHeader(m.spinner.View(), currentRate(m.history), m.width)
	chart := buildChart(m.history)
	treeContent := m.viewport.View()
	main := lipgloss.JoinVertical(lipgloss.Left, header, chart, treeContent)
	helpView := m.help.View(m.keys)
	return appPad.Render(lipgloss.JoinVertical(lipgloss.Left, main, helpView))
}

// ---------- Header / Chart ----------
func buildHeader(sp string, rate int, width int) string {
	rateStyled := okText
	switch {
	case rate > 50:
		rateStyled = danger
	case rate > 10:
		rateStyled = warn
	}

	title := titlePill.Render("🚀 Kernel Process Monitor")
	stats := dim.Render("Activity | Rate: ") + rateStyled.Render(fmt.Sprintf("%d p/s", rate))

	top := lipgloss.JoinHorizontal(lipgloss.Center, sp, " ", title)
	content := lipgloss.JoinVertical(lipgloss.Center, top, stats)

	return headerPanel.Width(width-4).Align(lipgloss.Center).Render(content)
}

func buildChart(history []int) string {
	ticks := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	maxVal := 0
	for _, v := range history {
		if v > maxVal {
			maxVal = v
		}
	}
	var sb strings.Builder
	for _, v := range history {
		idx := 0
		if maxVal > 0 {
			idx = (v * (len(ticks) - 1) * 100) / (maxVal * 100)
		}
		sb.WriteRune(ticks[idx])
	}
	title := titlePill.Render("Activity")
	graph := lipgloss.NewStyle().Foreground(lipgloss.Color("#69C")).Render(sb.String())
	return lipgloss.JoinVertical(lipgloss.Left, title, graph)
}

// ---------- Modal ----------
func modal(w, h int, text string) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cBorder).
		Background(lipgloss.Color("#0B0E14")).
		Padding(1, 2).
		Render(text)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box)
}

// ---------- Tree ----------
func buildTreeCmd() tea.Cmd { return func() tea.Msg { return treeMsg(buildTreeFromProc()) } }

func buildTreeFromProc() []*processNode {
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	nodes := make(map[int]*processNode)
	for _, dir := range procDirs {
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}
		var ppid int
		var comm string
		if status, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			scanner := tea.NewProgram(nil) // no-op to avoid unused import; replaced below
			_ = scanner                  // keep linter happy
			// fallback: simple scan
			f := lipgloss.NewStyle() // avoid unused imports in minimal snippet
			_ = f
			// real scan:
			file := status
			defer file.Close()
			buf := make([]byte, 1<<12)
			n, _ := file.Read(buf)
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if strings.HasPrefix(line, "Name:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						comm = fields[1]
					}
				}
				if strings.HasPrefix(line, "PPid:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						ppid, _ = strconv.Atoi(fields[1])
					}
				}
			}
			nodes[pid] = &processNode{PID: pid, PPID: ppid, Comm: comm}
		}
	}
	var roots []*processNode
	for pid, node := range nodes {
		if parent, ok := nodes[node.PPID]; ok {
			parent.Children = append(parent.Children, node)
		} else if pid != 0 {
			roots = append(roots, node)
		}
	}
	return roots
}

func renderTree(nodes []*processNode) string {
	var b strings.Builder
	for _, node := range nodes {
		renderNode(&b, node, "", true)
	}
	return b.String()
}

func renderNode(b *strings.Builder, node *processNode, prefix string, isLast bool) {
	branch := "├── "
	nextPref := "│   "
	if isLast {
		branch = "└── "
		nextPref = "    "
	}
	name := lipgloss.NewStyle().Bold(true).Render(node.Comm)
	pid := dim.Render(fmt.Sprintf("(%d)", node.PID))
	fmt.Fprintf(b, "%s%s%s %s\n", prefix, branch, name, pid)
	for i, child := range node.Children {
		renderNode(b, child, prefix+nextPref, i == len(node.Children)-1)
	}
}

// ---------- Details ----------
func getProcessDetails(pid uint32) processDetails {
	d := processDetails{PID: fmt.Sprintf("%d", pid)}
	base := fmt.Sprintf("/proc/%d", pid)
	if cmdline, err := os.ReadFile(base + "/cmdline"); err == nil {
		d.Cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
	}
	if file, err := os.Open(base + "/status"); err == nil {
		defer file.Close()
		buf := make([]byte, 1<<12)
		n, _ := file.Read(buf)
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if strings.HasPrefix(line, "State:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					d.Status = fields[1]
				}
			}
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					d.PPID = fields[1]
				}
			}
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					d.User = fields[1]
				}
			}
		}
	}
	return d
}

// ---------- Tick ----------
func tick() tea.Cmd { return tea.Tick(200*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} }) }

// ---------- main ----------
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.SysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())

	go func() {
		defer rd.Close()
		var eventBpf struct {
			PID  uint32
			_    [4]byte
			Comm [16]byte
		}
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &eventBpf); err != nil {
				continue
			}
			p.Send(newProcessMsg{
				PID:  eventBpf.PID,
				Comm: string(eventBpf.Comm[:bytes.IndexByte(eventBpf.Comm[:], 0)]),
				Time: time.Now(),
			})
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
