// MRT - default (sample-independent) heuristic flags.
//
// Every flag below describes a behavior, not a sample: Defender tampering,
// encoded execution, credential-store theft, wallet/token theft,
// anti-analysis and evasion, ransomware/wiper shaping, exfil channels,
// persistence, process injection and downloader-launcher pairs. All patterns
// are matched case-insensitively (plus UTF-16LE) against executable content
// only - docs and configs (.md/.txt/.log/.csv/.xml/.html/.json) are skipped
// - and, for JARs, against decompressed entries plus entry names.
//
// Conservative by design: no single category can convict on its own.
// SUSPICIOUS needs >=5 points across >=2 independent categories,
// CONFIRMED needs >=8 points across >=3. The strongest single category
// contributes 3 points.
package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Full credential-store queries (2 pts each inside credTheft; the short
// fragments below are 1 pt each and need a partner).
var genericCredFull = []string{
	"select origin_url, username_value, password_value from logins",
	"select host_key, name, encrypted_value, path, expires_utc from cookies",
	"select username, uuid, access_token, refresh_token, expires from minecraft_users",
}

var genericCredShort = []string{
	"from logins",
	"from cookies",
	"login data",
	"web data",
}

// Defender / security-product tampering. Any single hit opens the
// defender category (3 pts); it still needs a companion category.
var genericDefender = []string{
	"add-mppreference",
	"set-mppreference",
	"disablerealtimemonitoring",
	"disablebehaviormonitoring",
	"disableioavprotection",
	"disablescriptscanning",
}

// AMSI bypass primitives (medium support, 1 pt each listing - the category
// itself is 1 pt and only ever a companion).
var genericAMSI = []string{
	"amsiscanbuffer",
	"amsiinitfailed",
}

// Anti-analysis / evasion signals. Needs >=2 distinct hits to open the
// evasion category (2 pts).
//
// Deliberately narrow: debugger/VM API names (isdebuggerpresent,
// ntqueryinformationprocess, vmware, ...) live in every debugger, in
// ntdll/ntoskrnl which implement them, and in VM guest tools. Likewise
// "unhook" matches the UnhookWindowsHookEx import in any GUI app, PEB and
// hypervisor driver strings ship in IDA's own debugger plugins, so those
// all flagged IDA, x64dbg and Windows itself. What remains are sandbox
// artifacts and the PEB BeingDebugged check, which co-occur in stealers
// but not in legitimate system components or dev tools.
var genericEvasion = []string{
	"sbiedll",
	"sandboxie",
	"beingdebugged",
}

// Ransomware / wiper shaping: backup-kill and disk-overwrite primitives.
// Needs >=2 distinct hits (2 pts) - one backup reference alone (e.g. in
// admin or backup tools) scores nothing.
var genericRansomware = []string{
	"vssadmin",
	"delete shadows",
	"wbadmin",
	"delete catalog",
	"bcdedit",
	"recoveryenabled",
	"wevtutil",
	"clear-log",
	"cipher /w",
	"\\\\.\\physicaldrive",
}

// Wallet / token theft: crypto-wallet and key-store paths. Needs >=2
// distinct hits (2 pts) - a lone "wallet.dat" also matches legitimate
// crypto software, so it can only ever be a companion signal.
var genericWallet = []string{
	"wallet.dat",
	"electrum",
	"exodus",
	"ledger live",
	"trezor",
	"metamask",
	"local state",
	"seed phrase",
	"recovery phrase",
}

// Process-injection APIs. Needs >=2 distinct imports to open the
// injection category (2 pts); single imports are too common in
// legitimate software (updaters, launchers, AV).
var genericInjectionAPIs = []string{
	"writeprocessmemory",
	"createremotethread",
	"virtualallocex",
	"ntunmapviewofsection",
	"zwunmapviewofsection",
	"setwindowshookex",
	"queueuserapc",
	"rtlcreateuserthread",
}

// Remote-exfil channel pivots with weights. Webhook/Telegram/ABE
// markers are 2 pts; the rest are 1 pt and need a partner.
var genericExfil2 = []string{
	"discord.com/api/webhooks",
	"discordapp.com/api/webhooks",
	"api.telegram.org/bot",
	"app_bound_encrypted_key",
}

var genericExfil1 = []string{
	"discord.com/api/v9/users/@me",
	"discord_desktop_core",
	"transfer.sh",
	"pastebin.com/raw",
	"gofile.io",
	"file.io",
	"catbox.moe",
}

// Downloader/launcher pairs. Each pair is one 2-pt signal; lone
// occurrences (e.g. "http" or "rundll32" by itself) score nothing.
type genericPair struct {
	a   []string
	b   []string
	why string
}

var genericDownloaderPairs = []genericPair{
	{a: []string{"certutil"}, b: []string{"-decode", "-urlcache"}, why: "certutil downloader (certutil + decode/urlcache)"},
	{a: []string{"bitsadmin"}, b: []string{"/transfer"}, why: "bitsadmin downloader (bitsadmin + /transfer)"},
	{a: []string{"invoke-webrequest", "invoke-restmethod", "downloadfile", "downloadstring"}, b: []string{"-outfile", "-uri", "http"}, why: "scripted download (IWR/DownloadFile + out-file/URL)"},
	{a: []string{"mshta"}, b: []string{"http"}, why: "mshta remote execution (mshta + URL)"},
	{a: []string{"rundll32"}, b: []string{"http", "javascript:", ".sct"}, why: "rundll32 remote payload (rundll32 + URL/script)"},
	{a: []string{"regsvr32"}, b: []string{"scrobj.dll", ".sct"}, why: "squiblydoo execution (regsvr32 + scrobj/SCT)"},
}

// Persistence pairs: an autorun location plus a launcher.
var genericPersistencePairs = []genericPair{
	{a: []string{"currentversion\\run", "currentversion\\runonce"}, b: []string{"wscript", "powershell", "-windowstyle hidden", "-w hidden", ".vbs"}, why: "autorun wired to hidden script host (Run key + launcher)"},
	{a: []string{"schtasks"}, b: []string{"/create", "/tn "}, why: "scheduled-task creation (schtasks + create/task-name)"},
	{a: []string{"cmstp.exe"}, b: []string{".inf"}, why: "CMSTP UAC-bypass shape (cmstp.exe + INF)"},
	{a: []string{"fodhelper", "eventvwr", "computerdefaults"}, b: []string{"ms-settings", "shell\\open\\command"}, why: "UAC-bypass launcher shape (trusted binary + protocol/command)"},
	{a: []string{"sc.exe"}, b: []string{"binpath"}, why: "service installation (sc.exe + binpath)"},
	{a: []string{"reg add", "reg.exe"}, b: []string{"currentversion\\run"}, why: "registry persistence via CLI (reg + Run key)"},
	{a: []string{"programs\\startup", "start menu\\programs\\startup"}, b: []string{".lnk", ".vbs", ".bat", ".ps1"}, why: "startup-folder dropper (Startup dir + script/shortcut)"},
	{a: []string{"image file execution options"}, b: []string{"debugger"}, why: "IFEO hijack (Image File Execution Options + debugger)"},
	{a: []string{"appinit_dlls"}, b: []string{".dll"}, why: "AppInit persistence (AppInit_DLLs + DLL)"},
}

// Deceptive executable naming, e.g. invoice.pdf.exe. Filename-only,
// 1 pt, and only ever a companion to content flags.
var reDoubleExec = regexp.MustCompile(`(?i)\.(zip|jar|pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|mp4|mp3|avi|txt|iso|img|cab)\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$`)

// Content flags never run on docs/configs: their text legitimately
// quotes malware indicators (threat reports, configs, file lists).
var genericSkipExt = map[string]bool{
	".md": true, ".txt": true, ".log": true, ".csv": true,
	".xml": true, ".html": true, ".json": true,
}

// perf: precomputed byte forms for every generic pattern so the hot
// blobHas loop does zero allocs per file.
type genericPat struct {
	b []byte
	w []byte
}

var genericPatCache = map[string]genericPat{}

func init() {
	seen := map[string]bool{}
	add := func(pats ...string) {
		for _, p := range pats {
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			genericPatCache[p] = genericPat{b: []byte(p), w: utf16LE(p)}
		}
	}
	add(genericCredFull...)
	add(genericCredShort...)
	add(genericDefender...)
	add(genericAMSI...)
	add(genericEvasion...)
	add(genericRansomware...)
	add(genericWallet...)
	add(genericInjectionAPIs...)
	add(genericExfil2...)
	add(genericExfil1...)
	for _, pr := range genericDownloaderPairs {
		add(pr.a...)
		add(pr.b...)
	}
	for _, pr := range genericPersistencePairs {
		add(pr.a...)
		add(pr.b...)
	}
	add("powershell", "pwsh", "-encodedcommand", "frombase64string", "invoke-expression")
}

func trueExt(path string) string {
	base := strings.ToLower(filepath.Base(path))
	for _, suf := range []string{".infected", ".renamed", ".quarantined"} {
		base = strings.TrimSuffix(base, suf)
	}
	return filepath.Ext(base)
}

func blobHas(blob, lower []byte, pat string) bool {
	// perf: cached lower/wide forms avoid per-check []byte(pat) + utf16LE
	// allocs on every file (30+ patterns x thousands of files).
	if e, ok := genericPatCache[pat]; ok {
		if bytes.Contains(lower, e.b) {
			return true
		}
		if len(e.w) > 0 && bytes.Contains(blob, e.w) {
			return true
		}
		return false
	}
	if bytes.Contains(lower, []byte(pat)) {
		return true
	}
	if w := utf16LE(pat); len(w) > 0 && bytes.Contains(blob, w) {
		return true
	}
	return false
}

func anyOf(blob, lower []byte, pats []string) (bool, string) {
	for _, p := range pats {
		if blobHas(blob, lower, p) {
			return true, p
		}
	}
	return false, ""
}

func allPairs(blob, lower []byte, pairs []genericPair) []string {
	var out []string
	for _, pr := range pairs {
		hitA, _ := anyOf(blob, lower, pr.a)
		if !hitA {
			continue
		}
		if hitB, _ := anyOf(blob, lower, pr.b); hitB {
			out = append(out, pr.why)
		}
	}
	return out
}

type genericCat struct {
	name string
	pts  int
	why  []string
}

// scoreGenericPool evaluates one concatenated content pool (raw file
// bytes for executables/scripts, decompressed entries plus entry names
// for JARs). It never sees docs/configs; callers gate on trueExt.
func scoreGenericPool(path string, pool []byte, size int64, sha string) finding {
	return scoreGenericPoolLower(path, pool, bytes.ToLower(pool), size, sha)
}

func scoreGenericPoolLower(path string, pool, lower []byte, size int64, sha string) finding {
	f := finding{Path: path, Kind: "heuristic", Family: "generic", Verdict: "clean", YaraRules: yaraRulesByFamily["generic"]}
	f.Size = size
	f.SHA256 = sha

	var cats []genericCat
	add := func(name string, pts int, why ...string) {
		if len(why) > 0 {
			cats = append(cats, genericCat{name: name, pts: pts, why: why})
		}
	}

	if hit, pat := anyOf(pool, lower, genericDefender); hit {
		add("defender-tamper", 3, "security-product tampering: "+pat)
	}
	if hit, _ := anyOf(pool, lower, genericAMSI); hit {
		add("amsi-bypass", 1, "AMSI bypass primitive: amsiscanbuffer")
	}

	hasPS, _ := anyOf(pool, lower, []string{"powershell", "pwsh"})
	hasEnc, _ := anyOf(pool, lower, []string{"-encodedcommand", "frombase64string"})
	hasIEX, _ := anyOf(pool, lower, []string{"invoke-expression"})
	switch {
	case hasPS && hasEnc:
		add("encoded-exec", 3, "encoded execution: powershell + encoded/base64 payload")
	case hasIEX && hasEnc:
		add("encoded-exec", 3, "encoded execution: invoke-expression + base64 payload")
	}

	credPts := 0
	var credWhy []string
	for _, p := range genericCredFull {
		if blobHas(pool, lower, p) {
			credPts += 2
			credWhy = append(credWhy, "credential-store query: "+shortenPat(p))
		}
	}
	shortHits := 0
	for _, p := range genericCredShort {
		if blobHas(pool, lower, p) {
			shortHits++
		}
	}
	if shortHits >= 2 {
		credPts += 2
		credWhy = append(credWhy, "credential-store fragments (2+ of login-data/web-data/from-logins/from-cookies)")
	} else if shortHits == 1 && credPts > 0 {
		credPts++
	}
	if credPts >= 2 {
		add("cred-theft", 2, credWhy...)
	}

	exfilPts := 0
	var exfilWhy []string
	for _, p := range genericExfil2 {
		if blobHas(pool, lower, p) {
			exfilPts += 2
			exfilWhy = append(exfilWhy, "exfil channel: "+p)
		}
	}
	for _, p := range genericExfil1 {
		if blobHas(pool, lower, p) {
			exfilPts++
			exfilWhy = append(exfilWhy, "exfil pivot: "+p)
		}
	}
	if exfilPts >= 2 {
		add("remote-exfil", 2, exfilWhy...)
	}

	if why := allPairs(pool, lower, genericPersistencePairs); len(why) > 0 {
		add("persistence", 2, why...)
	}

	injHits := 0
	var injWhy []string
	for _, p := range genericInjectionAPIs {
		if blobHas(pool, lower, p) {
			injHits++
			injWhy = append(injWhy, p)
		}
	}
	if injHits >= 2 {
		add("injection", 2, "process-injection API set: "+strings.Join(injWhy, ", "))
	}

	if why := allPairs(pool, lower, genericDownloaderPairs); len(why) > 0 {
		add("downloader", 2, why...)
	}

	evasHits := 0
	var evasWhy []string
	for _, p := range genericEvasion {
		if blobHas(pool, lower, p) {
			evasHits++
			evasWhy = append(evasWhy, p)
		}
	}
	if evasHits >= 2 {
		add("evasion", 2, "anti-analysis set: "+strings.Join(evasWhy, ", "))
	}

	ransomHits := 0
	var ransomWhy []string
	for _, p := range genericRansomware {
		if blobHas(pool, lower, p) {
			ransomHits++
			ransomWhy = append(ransomWhy, p)
		}
	}
	if ransomHits >= 2 {
		add("ransomware-shape", 2, "backup-kill/disk set: "+strings.Join(ransomWhy, ", "))
	}

	walletHits := 0
	var walletWhy []string
	for _, p := range genericWallet {
		if blobHas(pool, lower, p) {
			walletHits++
			walletWhy = append(walletWhy, p)
		}
	}
	if walletHits >= 2 {
		add("wallet-theft", 2, "wallet/key-store set: "+strings.Join(walletWhy, ", "))
	}

	stripped := strings.ToLower(filepath.Base(path))
	for _, suf := range []string{".infected", ".renamed", ".quarantined"} {
		stripped = strings.TrimSuffix(stripped, suf)
	}
	if reDoubleExec.MatchString(stripped) {
		add("deceptive-name", 1, "deceptive double extension (document/archive + executable)")
	}

	score := 0
	var reasons []string
	for _, c := range cats {
		score += c.pts
		reasons = append(reasons, c.why...)
	}
	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 8 && len(cats) >= 3:
		f.Verdict = "CONFIRMED"
	case score >= 5 && len(cats) >= 2:
		f.Verdict = "SUSPICIOUS"
	default:
		f.Verdict = "clean"
		if score == 0 {
			f.Reasons = nil
		}
	}
	return f
}

func shortenPat(p string) string {
	if len(p) > 64 {
		return p[:64]
	}
	return p
}

const genericRawCap = 8 << 20
const genericJarEntryCap = 2 << 20
const genericJarPoolCap = 8 << 20

func genericFileMeta(path string) (int64, string) {
	var size int64
	if st, err := os.Stat(path); err == nil {
		size = st.Size()
	}
	// perf: SHA deferred — filled by fillFindingSHA for hits only.
	// Hashing every clean file up front re-read up to 128MB per file.
	return size, ""
}

// scoreGenericFile runs the default flags over one raw file. ZIPs are
// transparently handled as entry-names plus decompressed entries so the
// same behavior flags apply to packed droppers.
func scoreGenericFile(path string) finding {
	size, sha := genericFileMeta(path)
	clean := finding{Path: path, Kind: "heuristic", Family: "generic", Verdict: "clean", Size: size, SHA256: sha, YaraRules: yaraRulesByFamily["generic"]}
	if genericSkipExt[trueExt(path)] {
		return clean
	}
	if names, blobs, ok := genericJarPool(path); ok {
		pool := bytes.Join(append([][]byte{[]byte(strings.Join(names, "\n"))}, blobs...), []byte("\n"))
		return scoreGenericPool(path, pool, size, sha)
	}
	fh, err := os.Open(path)
	if err != nil {
		return clean
	}
	defer fh.Close()
	data, _ := io.ReadAll(io.LimitReader(fh, genericRawCap))
	return scoreGenericPool(path, data, size, sha)
}

// genericJarPool collects ZIP entry names plus decompressed entry bodies
// up to per-entry and total caps. ok=false means "not a ZIP".
func genericJarPool(path string) (names []string, blobs [][]byte, ok bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, false
	}
	defer zr.Close()
	var total int64
	for _, e := range zr.File {
		names = append(names, e.Name)
		if e.FileInfo().IsDir() || e.UncompressedSize64 == 0 || e.UncompressedSize64 > genericJarEntryCap {
			continue
		}
		if total >= genericJarPoolCap {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, genericJarEntryCap))
		rc.Close()
		blobs = append(blobs, data)
		total += int64(len(data))
	}
	return names, blobs, true
}

// scoreGenericJar runs the default flags over a JAR/ZIP via its
// decompressed entries. Used as an extra candidate in scoreJarAll so the
// family scorers keep priority on ties.
func scoreGenericJar(path string) finding {
	size, sha := genericFileMeta(path)
	clean := finding{Path: path, Kind: "heuristic", Family: "generic", Verdict: "clean", Size: size, SHA256: sha, YaraRules: yaraRulesByFamily["generic"]}
	names, blobs, ok := genericJarPool(path)
	if !ok {
		return clean
	}
	pool := bytes.Join(append([][]byte{[]byte(strings.Join(names, "\n"))}, blobs...), []byte("\n"))
	return scoreGenericPool(path, pool, size, sha)
}

// scoreRaw runs the family scorer plus the default flags and keeps the
// stronger verdict (family wins ties - its reasons are more specific).
//
// perf: shared single-read path — the old version opened + read + lowered
// every file twice (family 16MB + generic 8MB) and hashed it twice. Here we
// stat once, read up to 16MB once, lower once, and reuse the buffers for
// both scorers. SHA is deferred to fillFindingSHA (hits only).
func scoreRaw(path string) finding {
	st, err := os.Stat(path)
	if err != nil {
		// matches old behavior: both scorers clean on missing file.
		return bestFinding(scoreRawFamily(path), scoreGenericFile(path), true)
	}
	size := st.Size()
	// generic skip gate (family still runs on docs).
	genericSkipped := genericSkipExt[trueExt(path)]

	if size > 100<<20 {
		// family would return "skipped: >100MB" clean; generic still gets
		// first 8MB. Preserve that exact semantic without double-open.
		if genericSkipped {
			f := finding{Path: path, Kind: "exe-variant", Verdict: "clean", Size: size}
			f.Reasons = append(f.Reasons, "skipped: >100MB")
			return f
		}
		fh, err := os.Open(path)
		if err != nil {
			return bestFinding(scoreRawFamily(path), scoreGenericFile(path), true)
		}
		defer fh.Close()
		data, _ := io.ReadAll(io.LimitReader(fh, genericRawCap))
		lower := bytes.ToLower(data)
		fam := finding{Path: path, Kind: "exe-variant", Verdict: "clean", Size: size}
		fam.Reasons = append(fam.Reasons, "skipped: >100MB")
		gen := scoreGenericPoolLower(path, data, lower, size, "")
		return bestFinding(fam, gen, true)
	}

	fh, err := os.Open(path)
	if err != nil {
		return bestFinding(scoreRawFamily(path), scoreGenericFile(path), true)
	}
	defer fh.Close()

	const preRead = 2 << 20
	const familyCap = 16 << 20
	head, _ := io.ReadAll(io.LimitReader(fh, preRead))
	lowerHead := bytes.ToLower(head)
	hasPrefilter := bytes.Contains(lowerHead, []byte("ntprofile")) ||
		bytes.Contains(lowerHead, []byte("apphost")) ||
		bytes.Contains(lowerHead, []byte("spec_from_file_location")) ||
		bytes.Contains(lowerHead, []byte("donki")) ||
		bytes.Contains(lowerHead, []byte("abe_decrypt_")) ||
		bytes.Contains(lowerHead, []byte("securitymanager")) ||
		bytes.Contains(lowerHead, []byte("majanito")) ||
		bytes.Contains(lowerHead, []byte("0x9044")) ||
		bytes.Contains(lowerHead, []byte("x-tracking-id")) ||
		bytes.Contains(lowerHead, []byte("discord_desktop_core")) ||
		bytes.Contains(lowerHead, []byte("app_bound_encrypted_key")) ||
		bytes.Contains(lowerHead, []byte("dqw4w9wgxcq")) ||
		bytes.Contains(lowerHead, []byte("/api/receive"))
	lp := strings.ToLower(path)

	familyEarlyExit := !hasPrefilter && !strings.HasSuffix(lp, "main.py") && !strings.Contains(lp, "index.js")
	if familyEarlyExit {
		isPE := strings.HasSuffix(lp, ".exe") || strings.HasSuffix(lp, ".dll")
		if isPE || size > 8<<20 {
			// family is clean without reading the rest; generic still
			// needs up to 8MB.
			fam := finding{Path: path, Kind: "exe-variant", Verdict: "clean", Size: size}
			if genericSkipped {
				return fam
			}
			var data []byte
			if int64(len(head)) >= size || int64(len(head)) >= genericRawCap {
				rest, _ := io.ReadAll(io.LimitReader(fh, genericRawCap-int64(len(head))))
				data = append(head, rest...)
			} else {
				data = head
			}
			gen := scoreGenericPoolLower(path, data, bytes.ToLower(data), size, "")
			return bestFinding(fam, gen, true)
		}
	}

	// Full path: family needs up to 16MB.
	var data []byte
	if int64(len(head)) >= size || int64(len(head)) >= preRead {
		rest, _ := io.ReadAll(io.LimitReader(fh, familyCap-int64(len(head))))
		data = append(head, rest...)
	} else {
		data = head
	}
	ensureRawMarkerCache()
	lowerFull := bytes.ToLower(data)
	hits := matchRawMarkers(data, lowerFull)
	fam := finishRawFamily(path, size, lp, hits)

	if genericSkipped {
		return fam
	}
	// Reuse lowerFull prefix for generic when lengths align (ASCII fast
	// path); otherwise fall back to a separate ToLower (rare Unicode edge).
	poolLen := len(data)
	if poolLen > genericRawCap {
		poolLen = genericRawCap
	}
	pool := data[:poolLen]
	var poolLower []byte
	if len(lowerFull) == len(data) && poolLen <= len(lowerFull) {
		poolLower = lowerFull[:poolLen]
	} else {
		poolLower = bytes.ToLower(pool)
	}
	gen := scoreGenericPoolLower(path, pool, poolLower, size, "")
	return bestFinding(fam, gen, true)
}

func bestFinding(a, b finding, preferA bool) finding {
	ra, rb := verdictRank(a.Verdict), verdictRank(b.Verdict)
	if rb > ra {
		return b
	}
	if ra > rb {
		return a
	}
	if b.Score > a.Score {
		return b
	}
	if a.Score > b.Score {
		return a
	}
	if preferA {
		return a
	}
	return b
}
