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
	"strings"
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
