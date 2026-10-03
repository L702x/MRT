package main

import (
	"os"
	"testing"
)

func TestIsSelfBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	if !isSelfBinary(exe) {
		t.Fatalf("isSelfBinary(%q) = false, want true", exe)
	}
	tmp, err := os.CreateTemp("", "mrt-notself-*.exe")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if isSelfBinary(tmp.Name()) {
		t.Fatalf("isSelfBinary(%q) = true for unrelated file, want false", tmp.Name())
	}
}
