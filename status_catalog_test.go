package main

import (
	"strings"
	"testing"
)

func TestStatusCatalogCoversEveryOutcomeOnce(t *testing.T) {
	if len(statusCatalog) != int(statusCount)-1 {
		t.Fatalf("catalog contains %d entries for %d outcomes", len(statusCatalog), statusCount-1)
	}
	seen := make(map[scanStatus]bool)
	for _, definition := range statusCatalog {
		if definition.status <= statusUnset || definition.status >= statusCount || seen[definition.status] {
			t.Errorf("invalid or duplicate catalog status: %d", definition.status)
		}
		seen[definition.status] = true
		if strings.TrimSpace(definition.description) == "" || strings.ContainsAny(definition.description, "\r\n\t") {
			t.Errorf("status %q has an invalid help description: %q", definition.label, definition.description)
		}
	}
}
