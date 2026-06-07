// Package ui renders ladon's human-facing command output in a consistent
// terminal style: the LADON wordmark, a verdict badge, section headers and
// aligned status rows. Color is emitted only when writing to a real terminal
// (and NO_COLOR is unset), so piping, redirects and journald stay clean — and
// `-json` output never goes through here at all.
package ui

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// ANSI SGR codes.
const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cCyan   = "\x1b[36m"
	cGrey   = "\x1b[90m"
)

// Level is a status severity, mapped to a glyph and color.
type Level int

const (
	LevelOK Level = iota
	LevelWarn
	LevelFail
)

// labelWidth is the column the value starts at; labels are padded to it
// (rune-aware, so Cyrillic aligns).
const labelWidth = 22

// bannerArt is the LADON wordmark (figlet "ANSI Shadow").
const bannerArt = `██╗      █████╗ ██████╗  ██████╗ ███╗   ██╗
██║     ██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██║     ███████║██║  ██║██║   ██║██╔██╗ ██║
██║     ██╔══██║██║  ██║██║   ██║██║╚██╗██║
███████╗██║  ██║██████╔╝╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═══╝`

// Tagline is ladon's one-line descriptor shown under the wordmark.
const Tagline = "anti-dpi engine"

// Subtitle builds the dim line under the banner:
// "anti-dpi engine · <cmd> · <version>".
func Subtitle(cmd, version string) string {
	if version == "" {
		version = "dev"
	}
	return Tagline + " · " + cmd + " · " + version
}

// Style carries whether color is enabled for a particular writer.
type Style struct{ color bool }

// For returns a Style for w. Color is on only when w is a character device
// (a terminal) and NO_COLOR is unset.
func For(w io.Writer) Style { return Style{color: colorEnabled(w)} }

// Forced returns a Style with color explicitly set — used to render a report
// body into a buffer for the full-screen view, where the eventual destination
// is a terminal even though the buffer isn't.
func Forced(color bool) Style { return Style{color: color} }

// Term reports whether decorated output (color, banner) is active — i.e. we're
// writing to a real terminal. Data commands gate their banner on this so pipes
// and greps stay clean.
func (s Style) Term() bool { return s.color }

// Pad right-pads s to n display columns (rune-aware; our glyphs are width 1).
func Pad(s string, n int) string { return padRight(s, n) }

func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (s Style) wrap(code, text string) string {
	if !s.color {
		return text
	}
	return code + text + cReset
}

func (s Style) Bold(t string) string   { return s.wrap(cBold, t) }
func (s Style) Red(t string) string    { return s.wrap(cRed, t) }
func (s Style) Green(t string) string  { return s.wrap(cGreen, t) }
func (s Style) Yellow(t string) string { return s.wrap(cYellow, t) }
func (s Style) Cyan(t string) string   { return s.wrap(cCyan, t) }
func (s Style) Dim(t string) string    { return s.wrap(cGrey, t) }
func (s Style) head(t string) string   { return s.wrap(cBold+cCyan, t) }

func (s Style) colorFor(l Level, t string) string {
	switch l {
	case LevelFail:
		return s.Red(t)
	case LevelWarn:
		return s.Yellow(t)
	default:
		return s.Green(t)
	}
}

func (s Style) glyph(l Level) string {
	switch l {
	case LevelFail:
		return s.Red("✖")
	case LevelWarn:
		return s.Yellow("▲")
	default:
		return s.Green("✔")
	}
}

// Banner prints the LADON wordmark (cyan) and a dim subtitle line.
func (s Style) Banner(w io.Writer, subtitle string) {
	for _, line := range strings.Split(bannerArt, "\n") {
		fmt.Fprintln(w, "  "+s.Cyan(line))
	}
	if subtitle != "" {
		fmt.Fprintln(w, "  "+s.Dim(subtitle))
	}
	fmt.Fprintln(w)
}

// Badge prints the rounded verdict box: a colored dot plus bold text, with the
// border tinted to the level.
func (s Style) Badge(w io.Writer, l Level, text string) {
	inner := "  ●  " + text + "  "
	width := utf8.RuneCountInString(inner)
	bar := strings.Repeat("─", width)
	fmt.Fprintln(w, "  "+s.colorFor(l, "╭"+bar+"╮"))
	fmt.Fprintln(w, "  "+s.colorFor(l, "│")+"  "+s.colorFor(l, "●")+"  "+s.Bold(text)+"  "+s.colorFor(l, "│"))
	fmt.Fprintln(w, "  "+s.colorFor(l, "╰"+bar+"╯"))
}

// Section prints a section header.
func (s Style) Section(w io.Writer, title string) {
	fmt.Fprintln(w, "  "+s.head(title))
}

// Row prints a status row: a level glyph, the label (padded), and a dim value.
// When the label is wider than the value column, the value wraps to the next
// line (indented) so the columns never collide.
func (s Style) Row(w io.Writer, l Level, label, value string) {
	if value != "" && utf8.RuneCountInString(label) > labelWidth {
		fmt.Fprintf(w, "   %s %s\n", s.glyph(l), label)
		fmt.Fprintf(w, "       %s\n", s.Dim(value))
		return
	}
	fmt.Fprintf(w, "   %s %s%s\n", s.glyph(l), padRight(label, labelWidth), s.Dim(value))
}

// Info prints a neutral (judgement-free) row with a dim bullet — for status/why
// where a line is a fact, not a pass/fail.
func (s Style) Info(w io.Writer, label, value string) {
	fmt.Fprintf(w, "   %s %s%s\n", s.Dim("·"), padRight(label, labelWidth), value)
}

// FixLine prints an indented suggested-fix line under a failing row.
func (s Style) FixLine(w io.Writer, fix string) {
	fmt.Fprintln(w, "     "+s.Dim("fix: "+fix))
}

// padRight pads s with spaces to n display columns (rune count; the glyphs we
// use are all single-width), always leaving at least one trailing space.
func padRight(s string, n int) string {
	r := utf8.RuneCountInString(s)
	if r >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-r)
}

// Screen shows content on the alternate screen buffer as a simple full-window
// pager: the content (banner included) scrolls with ↑/↓/j/k, a status bar is
// pinned to the bottom row, and q/Esc restores the previous screen with no
// scrollback clutter. Terminal/Linux only — if /dev/tty can't be opened (piped,
// non-tty, Windows) it just prints the content inline and returns.
func Screen(content string) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Print(content)
		return
	}
	defer tty.Close()

	st := Style{color: true}

	// Single-keypress input: no echo, no line buffering.
	saved, _ := sttyOut(tty, "-g")
	if saved != "" {
		_ = sttyRun(tty, "-echo", "-icanon", "min", "1", "time", "0")
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		fmt.Fprint(tty, "\x1b[?25h\x1b[?1049l") // show cursor, leave alt screen
		if saved != "" {
			_ = sttyRun(tty, saved)
		}
	}
	// Restore on Ctrl-C / SIGTERM too, not just normal return.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigs; restore(); os.Exit(130) }()
	defer func() { signal.Stop(sigs); restore() }()

	fmt.Fprint(tty, "\x1b[?1049h\x1b[?25l") // enter alt screen, hide cursor

	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	offset := 0
	// draw paints one frame and returns the body-window height, clamping offset.
	draw := func() (win int) {
		rows, cols := termSize(tty)
		win = rows - 1 // last row reserved for the status bar
		if win < 1 {
			win = 1
		}
		maxOff := len(lines) - win
		if maxOff < 0 {
			maxOff = 0
		}
		if offset > maxOff {
			offset = maxOff
		}
		if offset < 0 {
			offset = 0
		}
		fmt.Fprint(tty, "\x1b[2J\x1b[H")
		for i := 0; i < win; i++ {
			if li := offset + i; li < len(lines) {
				fmt.Fprintln(tty, lines[li])
			} else {
				fmt.Fprintln(tty)
			}
		}
		hint := " q — выход "
		if len(lines) > win {
			last := offset + win
			if last > len(lines) {
				last = len(lines)
			}
			hint = fmt.Sprintf(" q выход · ↑/↓/j/k прокрутка · %d–%d/%d ", offset+1, last, len(lines))
		}
		fmt.Fprintf(tty, "\x1b[%d;1H%s", rows, st.bar("└─", hint, "─┘", cols))
		return win
	}

	win := draw()
	for {
		switch readScreenKey(tty) {
		case "q":
			return
		case "up":
			offset--
			win = draw()
		case "down":
			offset++
			win = draw()
		case "pgup":
			offset -= win
			win = draw()
		case "pgdn":
			offset += win
			win = draw()
		case "top":
			offset = 0
			win = draw()
		case "bottom":
			offset = len(lines)
			win = draw()
		default:
			// When everything fits, any key dismisses (no scrolling needed).
			if len(lines) <= win {
				return
			}
		}
	}
}

// readScreenKey reads one logical key from the tty: q/Esc/Ctrl-C → "q", arrows
// and j/k/space → scroll, g/G → top/bottom. Arrow escape sequences are read
// with a short deadline so a lone Esc doesn't block.
func readScreenKey(tty *os.File) string {
	b := make([]byte, 1)
	n, err := tty.Read(b)
	if err != nil || n == 0 {
		return ""
	}
	switch b[0] {
	case 'q', 'Q', 3:
		return "q"
	case 'j', ' ':
		return "down"
	case 'k':
		return "up"
	case 'g':
		return "top"
	case 'G':
		return "bottom"
	case 0x1b:
		seq := make([]byte, 3)
		_ = tty.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		m, _ := tty.Read(seq)
		_ = tty.SetReadDeadline(time.Time{})
		if m >= 2 && seq[0] == '[' {
			switch seq[1] {
			case 'A':
				return "up"
			case 'B':
				return "down"
			case '5':
				return "pgup"
			case '6':
				return "pgdn"
			}
		}
		return "q" // lone Esc
	}
	return "other"
}

// bar builds a full-width rule: left corner + a tinted label + fill + right
// corner, padded to cols columns.
func (s Style) bar(left, label, right string, cols int) string {
	fillN := cols - utf8.RuneCountInString(left+label+right)
	if fillN < 0 {
		fillN = 0
	}
	return s.Cyan(left) + s.head(label) + s.Cyan(strings.Repeat("─", fillN)+right)
}

// termSize asks the tty for its size via stty, defaulting to 24x80.
func termSize(tty *os.File) (rows, cols int) {
	rows, cols = 24, 80
	if out, err := sttyOut(tty, "size"); err == nil {
		fmt.Sscanf(out, "%d %d", &rows, &cols)
	}
	if rows < 5 {
		rows = 24
	}
	if cols < 20 {
		cols = 80
	}
	return rows, cols
}

func sttyOut(tty *os.File, args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = tty
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func sttyRun(tty *os.File, args ...string) error {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = tty
	return cmd.Run()
}
