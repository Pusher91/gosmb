package main

import (
	"fmt"
	"io"
	"strings"
)

type scanSummary struct {
	attempted, completed       int
	shares, readable, writable int
	outcomes                   [statusCount]int
}

func (s *scanSummary) Add(result Result, completed bool) {
	s.attempted++
	if completed {
		s.completed++
	}
	var firstFailedShare *ShareResult
	s.shares += len(result.Shares)
	for i := range result.Shares {
		share := &result.Shares[i]
		if firstFailedShare == nil && shareStatus(*share) != statusOK {
			firstFailedShare = share
		}
		if share.Read == Allowed {
			s.readable++
		}
		if share.Write == Allowed {
			s.writable++
		}
	}
	// Count each host once, using the same host/share/cleanup precedence as
	// its rows. Preserve known failures when cancellation interrupts the host.
	outcome := resultStatus(result, firstFailedShare)
	if !completed && (outcome == statusOK || outcome == statusNoShares) {
		outcome = statusCanceled
	}
	s.outcomes[outcome]++
}

func (s *scanSummary) Print(out io.Writer, total int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Summary: %d/%d hosts completed; %d interrupted; %d not started\n",
		s.completed, total, s.attempted-s.completed, max(0, total-s.attempted))
	b.WriteString("Host outcomes:")
	if s.attempted == 0 {
		b.WriteString(" none")
	} else {
		for _, definition := range statusCatalog {
			if count := s.outcomes[definition.status]; count > 0 {
				fmt.Fprintf(&b, " %s=%d", definition.label, count)
			}
		}
	}
	fmt.Fprintf(&b, "\nShares: %d found; %d readable; %d writable (metadata)\n", s.shares, s.readable, s.writable)
	_, err := writeOutputString(out, b.String())
	return err
}
