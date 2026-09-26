package main

import (
	"os"
	"strings"
	"testing"
)

func tempUnsignedPS1(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "mrt-sigtest-*.ps1")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("write-host hello"); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestAuthenticodeSigners(t *testing.T) {
	ntdll := `C:\Windows\System32\ntdll.dll`
	tmp := tempUnsignedPS1(t)
	got := authenticodeSigners([]string{ntdll, tmp})
	signer, ok := got[ntdll]
	if !ok {
		t.Fatalf("ntdll.dll not reported Valid: %v", got)
	}
	if !strings.Contains(strings.ToLower(signer), "microsoft") {
		t.Fatalf("unexpected ntdll signer: %q", signer)
	}
	if _, ok := got[tmp]; ok {
		t.Fatalf("unsigned script reported Valid")
	}
}

func TestFilterSignedGeneric(t *testing.T) {
	ntdll := `C:\Windows\System32\ntdll.dll`
	tmp := tempUnsignedPS1(t)
	in := []finding{
		{Path: ntdll, Family: "generic", Verdict: "SUSPICIOUS", Score: 6},
		{Path: tmp, Family: "generic", Verdict: "SUSPICIOUS", Score: 5},
		{Path: ntdll, Family: "donki", Verdict: "CONFIRMED", Score: 10},
	}
	out := filterSignedGeneric(in)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2 (signed generic dropped): %+v", len(out), out)
	}
	for _, f := range out {
		if f.Path == ntdll && f.Family == "generic" {
			t.Fatalf("signed generic finding was not skipped")
		}
	}
}

