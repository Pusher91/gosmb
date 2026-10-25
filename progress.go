package main

import (
	"fmt"
	"io"
	"math/bits"
)

const clearProgressLine = "\r\x1b[2K"

// progressDisplay owns only the current terminal line. Call Clear before
// printing rows or diagnostics, then Update to restore the footer below them.
// Completed-host accounting belongs to the caller, not this renderer.
type progressDisplay struct {
	out     io.Writer
	enabled bool
	total   int
	visible bool
}

func newProgress(out io.Writer, enabled bool, total int) *progressDisplay {
	if total < 0 {
		total = 0
	}
	return &progressDisplay{out: out, enabled: enabled, total: total}
}

func (p *progressDisplay) label(completed int) string {
	if completed < 0 {
		completed = 0
	}
	if completed > p.total {
		completed = p.total
	}
	percent := 0
	if p.total > 0 {
		// Keep integer-floor percentages without overflowing on large counts.
		hi, lo := bits.Mul64(uint64(completed), 100)
		scaled, _ := bits.Div64(hi, lo, uint64(p.total))
		percent = int(scaled)
	}
	return fmt.Sprintf("Progress: %d%% (%d/%d hosts completed)", percent, completed, p.total)
}

func (p *progressDisplay) write(text string, visible bool) error {
	n, err := io.WriteString(p.out, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err == nil {
		p.visible = visible
	} else if n > 0 {
		// A partial footer may still need clearing during orderly shutdown.
		p.visible = true
	}
	return err
}

func (p *progressDisplay) Update(completed int) error {
	if !p.enabled {
		return nil
	}
	return p.write(clearProgressLine+p.label(completed), true)
}

func (p *progressDisplay) Clear() error {
	if !p.enabled || !p.visible {
		return nil
	}
	return p.write(clearProgressLine, false)
}

func (p *progressDisplay) Finish(completed int, interrupted bool) error {
	if !p.enabled {
		return nil
	}
	label := p.label(completed)
	if interrupted {
		label += " (interrupted)"
	}
	// A newline leaves the shell prompt below the completed footer. Nothing
	// moves the cursor up or erases previously printed result rows.
	return p.write(clearProgressLine+label+"\n", false)
}
