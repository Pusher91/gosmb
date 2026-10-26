package main

import (
	"cmp"
	"slices"
	"strings"

	"gosmb/internal/smbwire"
)

type discoveredShare struct {
	Name, Type, Comment string
}

func discoveredShares(shares []smbwire.Share) []discoveredShare {
	// Normalize once per name, not twice per sort comparison. Sort indices so
	// the protocol's original results and equal-name ordering stay intact.
	type namedIndex struct {
		name  string
		index int
	}
	order := make([]namedIndex, len(shares))
	for i, share := range shares {
		order[i] = namedIndex{strings.ToLower(share.Name), i}
	}
	slices.SortStableFunc(order, func(a, b namedIndex) int { return cmp.Compare(a.name, b.name) })
	result := make([]discoveredShare, len(shares))
	for i, entry := range order {
		share := shares[entry.index]
		kind := share.Type & 0xff
		typeName := "other"
		switch kind {
		case 0:
			typeName = "disk"
		case 1:
			typeName = "printer"
		case 2:
			typeName = "device"
		case 3:
			typeName = "ipc"
		}
		result[i] = discoveredShare{Name: share.Name, Type: typeName, Comment: share.Comment}
	}
	return result
}
