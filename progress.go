package main

import (
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

const clearProgressLine = "\r\x1b[2K"

// Direct terminal output uses one updating line. Piped output uses occasional
// plain lines without erasing or repositioning the pipe consumer's output.
type progressDisplay struct {
	out        io.Writer
	enabled    bool
	total      int
	visible    bool
	lines      bool
	lastUpdate time.Time
	budget     progressBudget
}

type progressBudget struct {
	concurrency int
	hostTimeout time.Duration
	delay       time.Duration
}

func newProgress(out io.Writer, enabled bool, total int) *progressDisplay {
	if total < 0 {
		total = 0
	}
	return &progressDisplay{out: out, enabled: enabled, total: total}
}

func (p *progressDisplay) SetScanBudget(concurrency int, hostTimeout, delay time.Duration) {
	p.budget = progressBudget{concurrency, hostTimeout, delay}
}

func (p *progressDisplay) liveLabel(completed int) string {
	label := p.label(completed)
	if p.budget.concurrency < 1 || p.budget.hostTimeout <= 0 || p.budget.delay < 0 {
		return label
	}
	completed = max(0, min(completed, p.total))
	remaining := p.total - completed
	seconds := 0.0
	if remaining > 0 {
		b := p.budget
		// Assume every remaining host needs its entire host timeout. A batch
		// is limited by either occupied worker slots or the launch interval.
		// Work in seconds to avoid overflowing Duration for large scans.
		timeout, delay := b.hostTimeout.Seconds(), b.delay.Seconds()
		batches, offset := (remaining-1)/b.concurrency, (remaining-1)%b.concurrency
		seconds = float64(batches)*max(timeout, float64(b.concurrency)*delay) + float64(offset)*delay + timeout
		if completed > 0 {
			// The next queued launch may still be waiting on its interval even
			// if all active hosts finished quickly. Its remaining wait is <= D.
			seconds += delay
		}
	}
	return label + " | Max ETA: " + formatMaxETA(seconds)
}

// Round up at the displayed precision: this is a settings-based scan budget,
// not a measured prediction or a deadline for blocked terminal/file output.
func formatMaxETA(seconds float64) string {
	seconds = math.Ceil(seconds)
	switch {
	case seconds < 60:
		return fmt.Sprintf("%.0fs", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm%02ds", int(seconds)/60, int(seconds)%60)
	case seconds < 86400:
		minutes := int(math.Ceil(seconds / 60))
		return fmt.Sprintf("%dh%02dm", minutes/60, minutes%60)
	default:
		hours := math.Ceil(seconds / 3600)
		return fmt.Sprintf("%.0fd%02.0fh", math.Floor(hours/24), math.Mod(hours, 24))
	}
}

// UseLines must precede the first update. It needs no terminal setup or cleanup.
func (p *progressDisplay) UseLines() { p.lines = true }

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
	n, err := writeOutputString(p.out, text)
	if err == nil {
		p.visible = visible
	} else if n > 0 {
		// A partial direct-terminal update may still need clearing at shutdown.
		p.visible = true
	}
	return err
}

func (p *progressDisplay) Update(completed int) error {
	if !p.enabled {
		return nil
	}
	if p.lines {
		now := time.Now()
		if !p.lastUpdate.IsZero() && (completed >= p.total || now.Sub(p.lastUpdate) < time.Second) {
			return nil
		}
		if err := p.write(p.liveLabel(completed)+"\n", false); err != nil {
			return err
		}
		p.lastUpdate = now
		return nil
	}
	return p.write(clearProgressLine+p.liveLabel(completed), true)
}

func (p *progressDisplay) Clear() error {
	if !p.enabled || !p.visible || p.lines {
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
	if p.lines {
		return p.write(label+"\n", false)
	}
	// A newline leaves the shell prompt below the completed footer. Nothing
	// moves the cursor up or erases previously printed result rows.
	return p.write(clearProgressLine+label+"\n", false)
}
