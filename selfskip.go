// MRT - self-binary exclusion.
//
// The scanner's own binary necessarily contains its detection strings as Go
// constants (NtProfileIndex, C2 domains, contract addresses, ...), so every
// MRT build matches its own family + generic heuristics. Encrypting the
// embedded YARA rules (see yara_crypto.go) hides the rule text from static
// scans, but at runtime the decrypted literals plus the Go markers would
// still flag any MRT copy. The fix here is to never treat our own binary as
// a candidate: skip it by path AND by content identity (size + SHA256, so
// renamed copies like mrt-test.exe are skipped too), and refuse to
// quarantine/delete it as a last line of defense.
//
// Content matching is size-gated: only files with exactly the same byte
// size as the running exe pay for a hash. Malware cannot exploit this to
// hide - it would have to be byte-identical to MRT itself.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	selfExePathCanon string
	selfExeSize      int64 = -1
	selfExeSHA256     string
	selfIdentityOnce  sync.Once
)

// initSelfIdentity snapshots the running binary's canonical path, size and
// SHA256 once. Fail-open: if the exe path cannot be resolved, the path gate
// is skipped but hashing still applies when available.
func initSelfIdentity() {
	selfIdentityOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil || exe == "" {
			return
		}
		canon := exe
		if p, err := filepath.EvalSymlinks(exe); err == nil && p != "" {
			canon = p
		}
		selfExePathCanon = strings.ToLower(filepath.Clean(canon))
		if st, err := os.Stat(canon); err == nil && !st.IsDir() {
			selfExeSize = st.Size()
		} else if st, err := os.Stat(exe); err == nil && !st.IsDir() {
			selfExeSize = st.Size()
		}
		// sha256File caps at 128MB; MRT binaries are a few MB.
		if h, err := sha256File(canon); err == nil && h != "" {
			selfExeSHA256 = strings.ToLower(h)
		} else if h, err := sha256File(exe); err == nil && h != "" {
			selfExeSHA256 = strings.ToLower(h)
		}
	})
}

// selfPathEqual reports whether path resolves to the running executable.
// Cheap: no file content reads.
func selfPathEqual(path string) bool {
	initSelfIdentity()
	if selfExePathCanon == "" || path == "" {
		return false
	}
	clean := strings.ToLower(filepath.Clean(expandPathEnv(path)))
	if clean == selfExePathCanon {
		return true
	}
	if abs, err := filepath.Abs(clean); err == nil {
		if strings.ToLower(filepath.Clean(abs)) == selfExePathCanon {
			return true
		}
		// Resolve symlinks/junctions for the candidate as well (one Lstat).
		if p, err := filepath.EvalSymlinks(abs); err == nil && p != "" {
			if strings.ToLower(filepath.Clean(p)) == selfExePathCanon {
				return true
			}
		}
	}
	return false
}

// isSelfBinary reports whether path IS the running MRT binary, either by
// path or by identical content (size + SHA256). Renamed copies
// (mrt-test.exe, mrt(1).exe, ...) are caught by the content gate.
func isSelfBinary(path string) bool {
	if selfPathEqual(path) {
		return true
	}
	initSelfIdentity()
	if selfExeSize < 0 || selfExeSHA256 == "" || path == "" {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() != selfExeSize {
		return false
	}
	h, err := sha256File(path)
	if err != nil || h == "" {
		return false
	}
	return strings.EqualFold(h, selfExeSHA256)
}

// isInDir reports whether path lies inside dir (separator-boundary match).
func isInDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	lp := strings.ToLower(filepath.Clean(path))
	ld := strings.ToLower(filepath.Clean(dir))
	return lp == ld || strings.HasPrefix(lp, ld+string(filepath.Separator))
}
