// MRT - CLI scan progress bar.
//
// While scanFiles() works through the candidate list, a single updating
// line in the main console shows a progress bar plus elapsed time and ETA:
//
//   Scanning [============>.................]  38.2% (382/1000) | elapsed 00:00:41 | ETA 00:01:06 | 9.3 files/s
//
// The bar writes directly to stdout with carriage returns (throttled to
// ~150ms) and deliberately bypasses logf/writeLog so mrt.log is not spammed
// with redraws. Verbose mode (-v/--verbose) keeps the detailed per-file
// output instead of the bar, and piped/non-terminal output falls back to
// throttled log lines. --no-progress disables all of it.
package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// progressBarWidth is the fixed bar width in characters. ASCII-only so it
// renders correctly in both conhost and Windows Terminal regardless of the
// active code page.
const progressBarWidth = 30

type scanProgress struct {
	total    int
	done     int64
	start    time.Time
	mu       sync.Mutex
	lastDraw time.Time
	lastLog  time.Time
	bar      bool
}

// isVerbose reports whether detailed output is on (-v/--verbose). main()
// merges the -v shorthand into fVerbose right after flag.Parse, so one
// check covers both spellings.
func isVerbose() bool {
	return fVerbose != nil && *fVerbose
}

// isTerminal reports whether stdout is an interactive console. When piped
// or redirected, carriage-return redraws would just litter the file, so the
// caller falls back to periodic log lines instead.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// startScanProgress prepares progress tracking for total files. The bar is
// only used for interactive, non-verbose runs; everything else gets
// throttled log lines (or nothing for tiny scans).
func startScanProgress(total int) *scanProgress {
	now := time.Now()
	p := &scanProgress{total: total, start: now, lastDraw: now, lastLog: now}
	p.bar = total > 0 && !*fNoProgress && !isVerbose() && isTerminal()
	return p
}

// fmtDur formats d as hh:mm:ss for elapsed/ETA displays.
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d / time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s%3600)/60, s%60)
}

// tick records one finished file and forwards progress (throttled).
func (p *scanProgress) tick() {
	if p == nil || p.total <= 0 {
		return
	}
	d := atomic.AddInt64(&p.done, 1)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bar {
		if now.Sub(p.lastDraw) >= 150*time.Millisecond || d >= int64(p.total) {
			p.draw(d, false)
			p.lastDraw = now
		}
		return
	}
	if now.Sub(p.lastLog) >= 5*time.Second || d >= int64(p.total) {
		p.logLine(d, now)
		p.lastLog = now
	}
}

// draw redraws the single progress line in place. All fields are
// fixed-width so a shorter line never leaves stale characters behind.
func (p *scanProgress) draw(done int64, final bool) {
	el := time.Since(p.start)
	pct := 0.0
	if p.total > 0 {
		pct = 100 * float64(done) / float64(p.total)
	}
	filled := int(pct / 100 * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	var bar string
	if filled >= progressBarWidth {
		bar = strings.Repeat("=", progressBarWidth)
	} else {
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(".", progressBarWidth-filled-1)
	}
	eta := "--:--:--"
	rate := 0.0
	if done > 0 && el > 0 {
		rate = float64(done) / el.Seconds()
		if done < int64(p.total) {
			eta = fmtDur(time.Duration(float64(el) / float64(done) * float64(int64(p.total)-done)))
		} else {
			eta = "00:00:00"
		}
	}
	fmt.Fprintf(os.Stdout, "\rScanning [%s] %5.1f%% (%d/%d) | elapsed %s | ETA %s | %.1f files/s",
		bar, pct, done, p.total, fmtDur(el), eta, rate)
	if final {
		fmt.Fprint(os.Stdout, "\n")
	}
}

// logLine emits a throttled one-shot progress line for verbose/piped runs.
func (p *scanProgress) logLine(done int64, now time.Time) {
	el := now.Sub(p.start)
	msg := fmt.Sprintf("[scan] %d/%d files (%.1f%%), elapsed %s",
		done, p.total, 100*float64(done)/float64(p.total), fmtDur(el))
	if done > 0 && done < int64(p.total) && el > 0 {
		msg += fmt.Sprintf(", ETA %s", fmtDur(time.Duration(float64(el)/float64(done)*float64(int64(p.total)-done))))
	}
	logf("%s", msg)
}

// finish completes the display: final bar state plus newline in bar mode
// (the per-file final tick already logged the last line otherwise).
func (p *scanProgress) finish() {
	if p == nil || p.total <= 0 {
		return
	}
	if !p.bar {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.draw(atomic.LoadInt64(&p.done), true)
}
