package tui

import (
	"fmt"
	"strings"
	"time"

	"mobius/pkg/branding"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles from centralized branding
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(branding.ColorPrimary)).
			MarginTop(1).
			MarginBottom(1)

	successStyle = branding.StyleSuccess

	errorStyle = branding.StyleError

	warningStyle = branding.StyleWarning

	infoStyle = branding.StyleInfo

	subtleStyle = branding.StyleSecondary
)

type LogLevel int

const (
	LogInfo LogLevel = iota
	LogSuccess
	LogWarning
	LogError
)

type LogMsg struct {
	Level   LogLevel
	Message string
	Time    time.Time
}

type Model struct {
	spinner  spinner.Model
	logs     []LogMsg
	quitting bool
	width    int
	height   int
}

func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(branding.ColorPrimary))

	return Model{
		spinner: s,
		logs:    []LogMsg{},
		width:   80,
		height:  24,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}

	case LogMsg:
		m.logs = append(m.logs, msg)
		// Keep only last 100 logs
		if len(m.logs) > 100 {
			m.logs = m.logs[1:]
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return subtleStyle.Render("Shutting down Mobius...\n")
	}

	var b strings.Builder

	// Title
	b.WriteString(titleStyle.Render("🚀 Mobius Server"))
	b.WriteString("\n")

	// Show last 15 logs
	startIdx := 0
	if len(m.logs) > 15 {
		startIdx = len(m.logs) - 15
	}

	for _, log := range m.logs[startIdx:] {
		timestamp := log.Time.Format("15:04:05")
		timeStr := subtleStyle.Render(fmt.Sprintf("[%s]", timestamp))

		var message string
		switch log.Level {
		case LogSuccess:
			message = successStyle.Render("✓ " + log.Message)
		case LogError:
			message = errorStyle.Render("✗ " + log.Message)
		case LogWarning:
			message = warningStyle.Render("⚠ " + log.Message)
		default:
			message = infoStyle.Render("• " + log.Message)
		}

		b.WriteString(fmt.Sprintf("%s %s\n", timeStr, message))
	}

	// Spinner at the bottom if not quitting
	if !m.quitting {
		b.WriteString("\n")
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
		b.WriteString(subtleStyle.Render("Running... Press Ctrl+C to stop"))
	}

	return b.String()
}

// Program represents a running TUI program
type Program struct {
	program *tea.Program
}

// Start creates and starts a new TUI program
func Start() *Program {
	p := tea.NewProgram(NewModel())
	
	go func() {
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %v\n", err)
		}
	}()

	// Give the TUI a moment to initialize
	time.Sleep(100 * time.Millisecond)

	return &Program{program: p}
}

// Log sends a log message to the TUI
func (p *Program) Log(level LogLevel, message string) {
	if p.program != nil {
		p.program.Send(LogMsg{
			Level:   level,
			Message: message,
			Time:    time.Now(),
		})
	}
}

// Info logs an info message
func (p *Program) Info(message string) {
	p.Log(LogInfo, message)
}

// Success logs a success message
func (p *Program) Success(message string) {
	p.Log(LogSuccess, message)
}

// Warning logs a warning message
func (p *Program) Warning(message string) {
	p.Log(LogWarning, message)
}

// Error logs an error message
func (p *Program) Error(message string) {
	p.Log(LogError, message)
}

// Quit stops the TUI program
func (p *Program) Quit() {
	if p.program != nil {
		p.program.Quit()
	}
}

// Suspend temporarily stops the TUI to allow terminal interaction
func (p *Program) Suspend() {
	if p.program != nil {
		p.program.Send(tea.Quit())
		time.Sleep(200 * time.Millisecond) // Give it time to cleanup
	}
}

// Resume restarts the TUI after suspension
func (p *Program) Resume() {
	if p.program != nil {
		newProgram := tea.NewProgram(NewModel())
		go func() {
			if _, err := newProgram.Run(); err != nil {
				fmt.Printf("Error running TUI: %v\n", err)
			}
		}()
		time.Sleep(100 * time.Millisecond)
		p.program = newProgram
	}
}
