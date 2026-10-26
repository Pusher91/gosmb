package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func BenchmarkParseTarget(b *testing.B) {
	maximumHostname := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	for _, tc := range []struct {
		name, input string
		want        Target
	}{
		{"single_label_hostname", "fileserver", Target{"fileserver", 445}},
		{"hostname", "fileserver.example", Target{"fileserver.example", 445}},
		{"absolute_hostname", "Fileserver.Example.", Target{"Fileserver.Example.", 445}},
		{"maximum_hostname", maximumHostname, Target{maximumHostname, 445}},
		{"hostname_port", "fileserver.example:1445", Target{"fileserver.example", 1445}},
		{"ipv4", "192.0.2.10", Target{"192.0.2.10", 445}},
		{"ipv4_port", "192.0.2.10:1445", Target{"192.0.2.10", 1445}},
		{"ipv6", "2001:db8::1", Target{"2001:db8::1", 445}},
		{"ipv6_port", "[2001:db8::1]:1445", Target{"2001:db8::1", 1445}},
		{"padded_port", "fileserver.example:" + strings.Repeat("0", 60000) + "445", Target{"fileserver.example", 445}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				target, err := parseTarget(tc.input)
				if err != nil || target != tc.want {
					b.Fatalf("target=%#v error=%v; want %#v", target, err, tc.want)
				}
			}
		})
	}
}

func TestTargetListZeroPaddedPortsPreserveEndpoints(t *testing.T) {
	padding := strings.Repeat("0", 60000)
	input := "First.Example:" + padding + "1445\n" +
		"first.example:1445\nSecond.Example:" + padding + "445\n"
	want := []Target{{"First.Example", 1445}, {"Second.Example", 445}}
	targets, err := parseTargetList(context.Background(), strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(targets, want) {
		t.Fatalf("zero-padded ports changed target identity: targets=%#v error=%v; want %#v", targets, err, want)
	}
}

func TestTargetListPaddedRecordsPreserveHostnamesAcrossBufferReuse(t *testing.T) {
	padding := strings.Repeat(" ", 60000)
	input := "\ufeff\u2003" + padding + "First.Example:1445\u00a0\n" +
		"\u2002Second.Example" + padding + "\n" +
		" #" + strings.Repeat("x", 60000) + "\n" +
		"\tThird.Example:2445" + padding + "\r\n"
	want := []Target{{"First.Example", 1445}, {"Second.Example", 445}, {"Third.Example", 2445}}
	targets, err := parseTargetList(context.Background(), strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(targets, want) {
		t.Fatalf("padded records changed retained targets: targets=%#v error=%v; want %#v", targets, err, want)
	}
}

func TestTargetListRejectsInvalidUTF8InComments(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"first line with BOM", "\ufeff # invalid \xff\n", "host-list line 1 is not valid UTF-8"},
		{"after valid target", "server\n\u2003# invalid \xff\n", "host-list line 2 is not valid UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := parseTargetList(context.Background(), strings.NewReader(tc.input))
			if targets != nil || err == nil || err.Error() != tc.want {
				t.Fatalf("invalid comment was skipped or retained partial targets: targets=%#v error=%v; want %q", targets, err, tc.want)
			}
		})
	}
}
