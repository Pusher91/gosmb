package main

import (
	"errors"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
)

func sharePage(t *testing.T, names []string, status uint32, resume uint32) []byte {
	t.Helper()
	entries := make([]mssrvs.ShareInfo1, len(names))
	for i, name := range names {
		entries[i] = mssrvs.ShareInfo1{Name: name, Comment: "fixture"}
	}
	page := mssrvs.NetShareEnumAllResponse{
		InfoStruct:   mssrvs.ShareEnumStruct{Level: 1, Level1: &mssrvs.ShareInfoContainer1{EntriesRead: uint32(len(entries)), Buffer: entries}},
		TotalEntries: uint32(len(entries)), ResumeHandle: &resume, WindowsError: status,
	}
	result, err := page.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEnumerationFollowsResumeCursorAndKeepsHiddenShares(t *testing.T) {
	calls := 0
	shares, err := enumeratePages("fixture", func(body []byte) ([]byte, error) {
		var request mssrvs.NetShareEnumAllRequest
		if err := request.Unmarshal(body); err != nil {
			t.Fatal(err)
		}
		calls++
		if request.InfoStruct.Level != 1 {
			t.Fatal("enumeration requested unnecessary extended metadata")
		}
		if calls == 1 {
			return sharePage(t, []string{"data", "hidden$"}, 234, 7), nil
		}
		if calls != 2 || request.ResumeHandle == nil || *request.ResumeHandle != 7 {
			t.Fatal("incorrect pagination cursor or extra request")
		}
		return sharePage(t, []string{"DATA", "last"}, 0, 0), nil
	})
	if err != nil || calls != 2 || len(shares) != 3 || shares[1].Name != "hidden$" || shares[2].Name != "last" {
		t.Fatalf("enumeration: %+v, %v, calls=%d", shares, err, calls)
	}
}

func TestEnumerationStopsOnRepeatedCursor(t *testing.T) {
	calls := 0
	shares, err := enumeratePages("fixture", func([]byte) ([]byte, error) {
		calls++
		return sharePage(t, []string{"data"}, 234, 5), nil
	})
	if err == nil || calls != 2 || len(shares) != 1 {
		t.Fatalf("repeated cursor was not bounded: calls=%d shares=%v error=%v", calls, shares, err)
	}
}

func TestEnumerationDeniedDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := enumeratePages("fixture", func([]byte) ([]byte, error) {
		calls++
		return sharePage(t, nil, 5, 0), nil
	})
	if !errors.Is(err, errRPCDenied) || calls != 1 {
		t.Fatalf("access denial: calls=%d error=%v", calls, err)
	}
}

func TestInvalidServerShareNamesAreNotProbed(t *testing.T) {
	for _, name := range []string{"", ".", "..", `..\data`, "host/share", "a:b", "bad\x1bname"} {
		if validShareName(name) {
			t.Errorf("accepted invalid share %q", name)
		}
	}
	for _, name := range []string{"C$", "IPC$", "Shared Documents", "données"} {
		if !validShareName(name) {
			t.Errorf("rejected valid share %q", name)
		}
	}
}
