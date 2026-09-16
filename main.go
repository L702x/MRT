// MRT - Made by L702x/Krotten/NotPetya (same person)
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const toolVersion = "1.5.0"

var (
	c2Domains = []string{
		"thisisafalsepositive.st",
		"sltnnt.ru",
		"silentnet.st",
	}
	c2IPs = []string{
		"185.178.208.191",
		"185.178.208.165",
	}
	contractAddress = "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a"
	operatorWallet  = "0x6767c6496541b530a5d1d0eb9b80bd5c7bf56767"

	weedhackContract = "0x1280a841Fbc1F883365d3C83122260E0b2995B74"
	getDomainSel    = "ce6d41de"
	fernetKey       = "74af664f79d1ef1436a4bf301788c7eb207570de60034b19d76df8e7aefc69b7"

	donkiContract   = "0x9044f5762e43b23ba91d124b51a045f1b51da652"
	donkiSelector   = "0x1f1bd692"
	donkiStage2Main = "dev.majanito.security.Main"
	donkiModuleSHA256 = "25b2e5e52c023efb7d83201a5fd0edfeca1642ef98cab7b8069f45ee6fd7269b"

	pipeName = `\\.\pipe\NtProfileSync`
	donkiPipePrefix = `\\.\pipe\abe_decrypt_`

	licGithubSHA256Prefix = "6d489af6292662d9e36d34ce49423784"
	iconSHA256Prefix      = "c888e51cbbfd3cd10a08cc48997a0c68"
	mainPySHA256          = "bc87ec291523785fd9f8b1925e92dbe5aa71af4a9dd631c794fc14efd9e5afb1"
)

var (
	fScanOnly     = flag.Bool("scan-only", false, "Only scan and report, do not remove anything")
	fFull         = flag.Bool("full", false, "Full scan: also walk all user profiles (slower). Default is quick common-places scan")
	fYes          = flag.Bool("yes", false, "Skip confirmation prompt (required for non-interactive removal)")
	fDryRun       = flag.Bool("dry-run", false, "Print what would be done without changing anything")
	fVerbose      = flag.Bool("verbose", false, "Verbose output (per-file scores, skipped dirs)")
	fQuarantine   = flag.String("quarantine-dir", "", "Quarantine directory (default %LOCALAPPDATA%\\MRT\\quarantine)")
	fExtraPath    = flag.String("extra-path", "", "Comma-separated extra paths to scan (e.g. for testing against sample dirs)")
	fDelete       = flag.Bool("delete", false, "Permanently delete droppers instead of quarantining (staging dir is always deleted)")
	fNoHarden     = flag.Bool("no-harden", false, "Skip hosts/firewall hardening")
	fYaraPath     = flag.String("yara-rules", "", "Single .yar file override (default: embedded rules plus every rules/*.yar next to the exe)")
	fRoots        = flag.String("roots", "", "Comma-separated scan roots override (default: common places). Use for fast targeted scans, e.g. --roots \"C:\\samples\"")
	fAllowSampleDir = flag.Bool("allow-sample-dir", false, "Allow quarantine/delete inside the C:\\MALWARE research collection (default: refuse; scan-only still works)")
	fListLaunchers = flag.Bool("list-launchers", false, "List known game launchers and which ones are installed, then exit")
)

func logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stdout, msg)
	writeLog(msg)
}

func vlogf(format string, a ...any) {
	if *fVerbose {
		msg := "[verbose] " + fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stdout, msg)
		writeLog(msg)
	}
}

func warnf(format string, a ...any) {
	msg := "[WARN] " + fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stdout, msg)
	writeLog(msg)
}

// outf/outln/outPrint mirror user-facing output to the console and to
// mrt.log so the log file holds everything the tool printed.
func outf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	msg = strings.TrimSuffix(msg, "\n")
	fmt.Fprintln(os.Stdout, msg)
	writeLog(msg)
}

func outln(a ...any) {
	msg := fmt.Sprintln(a...)
	msg = strings.TrimSuffix(msg, "\n")
	fmt.Fprintln(os.Stdout, msg)
	writeLog(msg)
}

func outPrint(a ...any) {
	msg := fmt.Sprint(a...)
	fmt.Fprint(os.Stdout, msg)
	writeLog(msg)
}

var (
	logFile *os.File
	logMu   sync.Mutex
)

// initLogFile opens (or creates) mrt.log in the directory the tool was
// run from and appends all subsequent output to it. Logging never stops
// the tool: if the file cannot be opened, the run continues on console.
func initLogFile() {
	wd, err := os.Getwd()
	if err != nil {
		outf("[WARN] cannot determine working directory for mrt.log: %v", err)
		return
	}
	path := filepath.Join(wd, "mrt.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		outf("[WARN] cannot open log file %s: %v (continuing without file logging)", path, err)
		return
	}
	logFile = f
	fmt.Fprintf(f, "\n=== MRT v%s run %s ===\n", toolVersion, time.Now().Format(time.RFC3339))
}

// closeLogFile flushes and releases mrt.log. Writes throughout the run
// are unbuffered, so os.Exit paths elsewhere in main lose nothing.
func closeLogFile() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		fmt.Fprintln(logFile, "=== run finished ===")
		logFile.Close()
		logFile = nil
	}
}

// writeLog appends msg to mrt.log with a per-line timestamp. Blank lines
// are preserved without a timestamp. Writes are unbuffered and mutex
// guarded so worker goroutines cannot interleave lines.
func writeLog(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile == nil {
		return
	}
	stamp := time.Now().Format("2006-01-02 15:04:05")
	for _, line := range strings.Split(msg, "\n") {
		if strings.TrimSpace(line) == "" {
			fmt.Fprintln(logFile, "")
			continue
		}
		fmt.Fprintf(logFile, "%s %s\n", stamp, line)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func expandEnvList(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, expandPathEnv(p))
	}
	return out
}

var reWinEnv = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

func expandPathEnv(p string) string {
	p = reWinEnv.ReplaceAllStringFunc(p, func(m string) string {
		if v := os.Getenv(m[1 : len(m)-1]); v != "" {
			return v
		}
		return m
	})
	return os.ExpandEnv(p)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 128<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runCmd(name string, args ...string) (string, int) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	return buf.String(), code
}

func isAdmin() bool {
	if runtime.GOOS != "windows" {

		return os.Geteuid() == 0
	}
	_, code := runCmd("net", "session")
	return code == 0
}

func quarantineDir() string {
	if *fQuarantine != "" {
		return *fQuarantine
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "MRT", "quarantine")
}

func stagingDir() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", "NtProfileIndex")
}

//go:embed rules/*.yar
var embeddedYaraFS embed.FS

var embeddedYaraTempDir string

var embeddedCleanMarkers = []string{
	"NtProfileIndex", "LOCALAPPDATA", "_spawn.log", "-restarted",
	"AppHost", "main.py", "python.exe", "jre-embedded",
	"X-Runtime-Env", "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a",
	"0xce6d41de", "ce6d41de", "sltnnt.ru", "thisisafalsepositive.st",
	"silentnet.st", "getDomain", `Microsoft\Windows`, "java.home",
	"Stealer spawned: pid=",
}

var embeddedStage2Markers = []string{
	"AppHost", "NtProfileIndex", "NtProfileSync", "X-Runtime-Env",
	"jre-embedded", "/shard/submitData", "/shard/submitLogs",
	"/shard/prefireMc", "/cdn/e/", "python312.zip", "staging-worker",
	fernetKey, "x-cdn-origin-verify", "trusted-upstream",
}

var yaraLiterals []string
var yaraRulesByFamily = map[string]string{}

var reYaraStringDef = regexp.MustCompile(`(?m)^\s*\$[A-Za-z0-9_]+\s*=\s*"((?:[^"\\]|\\.)+)"`)

func yaraRulesFiles() []string {
	if *fYaraPath != "" {
		return []string{*fYaraPath}
	}
	seen := map[string]bool{}
	var out []string
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "rules"), filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(wd, "rules"))
	}
	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(d, "*.yar"))
		for _, m := range matches {
			key := strings.ToLower(m)
			if !seen[key] {
				seen[key] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func embeddedYaraNames() []string {
	entries, err := embeddedYaraFS.ReadDir("rules")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yar") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func appendYaraLiterals(data []byte, seen map[string]bool) int {
	n := 0
	for _, m := range reYaraStringDef.FindAllSubmatch(data, -1) {
		lit := string(m[1])

		lit = strings.ReplaceAll(lit, `\"`, `"`)
		lit = strings.ReplaceAll(lit, `\\`, `\`)
		if len(lit) < 4 || len(lit) > 200 {
			continue
		}
		if !seen[lit] {
			seen[lit] = true
			yaraLiterals = append(yaraLiterals, lit)
			n++
		}
	}
	return n
}

func loadEmbeddedYara(seen map[string]bool) int {
	names := embeddedYaraNames()
	if len(names) == 0 {
		return 0
	}

	if embeddedYaraTempDir == "" {
		dir, err := os.MkdirTemp("", "mrt-yara-*")
		if err != nil {
			warnf("cannot create temp dir for embedded yara rules: %v", err)
			return 0
		}
		embeddedYaraTempDir = dir
	}
	loaded := 0
	for _, name := range names {
		data, err := embeddedYaraFS.ReadFile("rules/" + name)
		if err != nil {
			warnf("cannot read embedded yara rules %s: %v (skipping)", name, err)
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
		tmpPath := filepath.Join(embeddedYaraTempDir, name)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			warnf("cannot materialize embedded yara rules %s: %v", name, err)

		} else if _, ok := yaraRulesByFamily[base]; !ok {
			yaraRulesByFamily[base] = tmpPath
		}
		n := appendYaraLiterals(data, seen)
		vlogf("[yara] %d literals from embedded rules/%s", n, name)
		loaded++
	}
	return loaded
}

func loadYaraLiterals() {
	seen := map[string]bool{}

	if *fYaraPath != "" {
		data, err := os.ReadFile(*fYaraPath)
		if err != nil {
			warnf("cannot read yara rules %s: %v (skipping)", *fYaraPath, err)
			return
		}
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(*fYaraPath), filepath.Ext(*fYaraPath)))
		yaraRulesByFamily[base] = *fYaraPath
		n := appendYaraLiterals(data, seen)
		logf("[yara] loaded %d string literals from 1 rule file(s) (--yara-rules override)", len(yaraLiterals))
		vlogf("[yara] %d literals from %s", n, *fYaraPath)
		return
	}
	nEmbedded := loadEmbeddedYara(seen)
	files := yaraRulesFiles()
	nDisk := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			warnf("cannot read yara rules %s: %v (skipping)", path, err)
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))

		yaraRulesByFamily[base] = path
		n := appendYaraLiterals(data, seen)
		vlogf("[yara] %d literals from %s", n, path)
		nDisk++
	}
	if nEmbedded+nDisk == 0 {
		vlogf("no embedded or on-disk .yar rules found; using built-in literals")
		return
	}
	logf("[yara] loaded %d string literals from %d embedded + %d on-disk rule file(s)", len(yaraLiterals), nEmbedded, nDisk)
}

func externalYara() string {
	p, err := exec.LookPath("yara")
	if err != nil {
		return ""
	}
	return p
}

func confirmWithExternalYara(yaraBin, rules, file string) []string {
	out, code := runCmd(yaraBin, rules, file)
	if code != 0 {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 {
			names = append(names, parts[0])
		}
	}
	return names
}

type finding struct {
	Path      string
	Kind      string
	Family    string
	Score     int
	Verdict   string
	Reasons   []string
	SHA256    string
	Size      int64
	YaraHits  []string
	YaraRules string
}

func isSampleCollection(p string) bool {
	up := strings.ToUpper(filepath.Clean(p))
	return up == `C:\MALWARE` || strings.HasPrefix(up, `C:\MALWARE\`)
}

var reAssetBlob = regexp.MustCompile(`^assets/[a-z]{8}\.(bin|cache|dat|cfg|png)$`)

func scoreJar(path string) finding {
	f := finding{Path: path, Kind: "jar-dropper", Family: "silentnet", Verdict: "clean", YaraRules: yaraRulesByFamily["silentnet"]}
	st, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Size = st.Size()
	if h, err := sha256File(path); err == nil {
		f.SHA256 = h
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		f.Verdict = "clean"
		f.Reasons = append(f.Reasons, "not a readable zip")
		return f
	}
	defer zr.Close()

	score := 0
	var reasons []string
	hasLic, hasIcon := false, false
	var licSize, iconSize int64
	var licHash, iconHash string
	ghClasses := 0
	hasFabric := false
	var fabricData []byte
	hasManifestMC := false
	largeBlob := ""
	var largeBlobSize uint64
	jdkHits := map[string]bool{}
	plainHits := map[string]bool{}

	for _, e := range zr.File {
		name := e.Name
		switch name {
		case "LICENSE_github":
			hasLic = true
			licSize = int64(e.UncompressedSize64)
		case "assets/package/icon.png":
			hasIcon = true
			iconSize = int64(e.UncompressedSize64)
		case "fabric.mod.json":
			hasFabric = true
			if rc, err := e.Open(); err == nil {
				fabricData, _ = io.ReadAll(io.LimitReader(rc, 8192))
				rc.Close()
			}
		case "META-INF/MANIFEST.MF":
			if rc, err := e.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 4096))
				rc.Close()
				if bytes.Contains(data, []byte("Main-Class: com.github.")) {
					hasManifestMC = true
				}
			}
		}
		if strings.HasPrefix(name, "com/github/") && strings.HasSuffix(name, ".class") {
			ghClasses++
		}
		if reAssetBlob.MatchString(name) && e.UncompressedSize64 > 500*1024 {
			largeBlob = name
			largeBlobSize = e.UncompressedSize64
		}

		if (name == "LICENSE_github" || name == "assets/package/icon.png") && e.UncompressedSize64 < 1<<20 {
			if rc, err := e.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
				rc.Close()
				sum := sha256.Sum256(data)
				hx := hex.EncodeToString(sum[:])
				if name == "LICENSE_github" {
					licHash = hx
				} else {
					iconHash = hx
				}
			}
		}

		if strings.HasSuffix(name, ".class") && e.UncompressedSize64 < 2<<20 {
			if rc, err := e.Open(); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 2<<20))
				rc.Close()
				for _, m := range []string{"java/lang/ProcessBuilder", "createDirectories", "getenv", "ProcessBuilder$Redirect"} {
					if bytes.Contains(data, []byte(m)) {
						jdkHits[m] = true
					}
				}
				for _, m := range embeddedCleanMarkers {
					if bytes.Contains(data, []byte(m)) {
						plainHits[m] = true
					}
				}
			}
		}
	}

	if hasLic && licSize == 7047 && strings.HasPrefix(licHash, licGithubSHA256Prefix) {
		score += 3
		reasons = append(reasons, "LICENSE_github 7047B known SilentNet hash")
	} else if hasLic {
		score += 1
		reasons = append(reasons, "LICENSE_github present")
	}

	structAnchors := 0
	if hasLic {
		structAnchors++
	}
	if hasIcon {
		structAnchors++
	}
	if largeBlob != "" {
		structAnchors++
	}
	if hasFabric && isSilentNetFabric(fabricData) {
		structAnchors++
	}
	if hasManifestMC {
		structAnchors++
	}
	if structAnchors == 0 {
		f.Score = 0
		f.Verdict = "clean"
		f.Reasons = nil
		return f
	}
	if hasIcon && iconSize == 252 && strings.HasPrefix(iconHash, iconSHA256Prefix) {
		score += 3
		reasons = append(reasons, "assets/package/icon.png 252B known SilentNet hash")
	} else if hasIcon {
		score += 1
		reasons = append(reasons, "assets/package/icon.png present")
	}
	if hasFabric && isSilentNetFabric(fabricData) {
		score += 2
		reasons = append(reasons, "fabric.mod.json SilentNet template (package/sample)")
	} else if hasFabric {
		vlogf("%s: fabric.mod.json present but not SilentNet template", path)
	}
	if largeBlob != "" {
		score += 3
		reasons = append(reasons, fmt.Sprintf("encrypted payload blob %s (%d bytes)", largeBlob, largeBlobSize))
	}
	if ghClasses >= 6 {
		score += 2
		reasons = append(reasons, fmt.Sprintf("%d com/github/*.class obfuscated classes", ghClasses))
	} else if ghClasses >= 3 {
		score += 1
		reasons = append(reasons, fmt.Sprintf("%d com/github/*.class", ghClasses))
	}
	if hasManifestMC {
		score += 1
		reasons = append(reasons, "MANIFEST Main-Class: com.github.<random>")
	}
	if len(jdkHits) >= 3 {
		score += 2
		reasons = append(reasons, "JDK stealer triple (ProcessBuilder+createDirectories+getenv)")
	}
	if len(plainHits) >= 2 {
		score += 3
		names := make([]string, 0, len(plainHits))
		for k := range plainHits {
			names = append(names, strconv_k(k))
		}
		sort.Strings(names)
		reasons = append(reasons, "plaintext stage-1 markers: "+strings.Join(names, ", "))
	} else if len(plainHits) == 1 {
		score += 1
		for k := range plainHits {
			reasons = append(reasons, "plaintext marker: "+k)
		}
	}

	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 8:
		f.Verdict = "CONFIRMED"
		f.Kind = "jar-dropper"
	case score >= 5:
		f.Verdict = "SUSPICIOUS"
		f.Kind = "jar-dropper"
	default:
		f.Verdict = "clean"
	}
	return f
}

func strconv_k(s string) string {
	if len(s) > 48 {
		return s[:48]
	}
	return s
}

var weedhackFabricIDs = []string{`"krloader"`, `"loaderclient"`, `"prestigemod"`, `"rypton"`}

var weedhackStrong = []string{
	"0x1280a841Fbc1F883365d3C83122260E0b2995B74",
	"/api/delivery/handler",
	"/files/jar/module",
	"dev.majanito.Main",
	"dev/majanito/Main",
	"initializeWeedhack",
}

var weedhackSupport = []string{
	"jvmtp", "--jw", "eth_call", "receiver.cy", "cloudflare-dns.com/dns-query",
	"dns.google/resolve", "thread_silent", "getText",
}

var reJnicDir = regexp.MustCompile(`^native/[0-9a-f]{8,}/`)

func scoreWeedHackJar(path string) finding {
	f := finding{Path: path, Kind: "jar-weedhack", Family: "weedhack", Verdict: "clean", YaraRules: yaraRulesByFamily["weedhack"]}
	st, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Size = st.Size()
	if h, err := sha256File(path); err == nil {
		f.SHA256 = h
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		f.Verdict = "clean"
		f.Reasons = append(f.Reasons, "not a readable zip")
		return f
	}
	defer zr.Close()

	score := 0
	anchors := 0
	var reasons []string
	var fabricData []byte
	jnic := false
	silentBlob := false
	hasCfg := false
	hasDevJnic := false
	for _, e := range zr.File {
		if e.Name == "fabric.mod.json" {
			if rc, err := e.Open(); err == nil {
				fabricData, _ = io.ReadAll(io.LimitReader(rc, 8192))
				rc.Close()
			}
		}
		if reJnicDir.MatchString(e.Name) {
			jnic = true
		}
		if e.Name == "assets/thread_silent.dat" {
			silentBlob = true
		}
		if e.Name == "cfg.json" {
			hasCfg = true
		}
		if strings.HasPrefix(e.Name, "dev/jnic/") {
			hasDevJnic = true
		}
	}
	fabricLower := strings.ToLower(string(fabricData))
	for _, id := range weedhackFabricIDs {
		if strings.Contains(fabricLower, id) {
			score += 3
			anchors++
			reasons = append(reasons, "WeedHack fabric mod id "+id)
			break
		}
	}
	if jnic {
		score += 3
		anchors++
		reasons = append(reasons, "JNIC native/ payload dir (KrLoader-style native protection)")
	}
	if silentBlob {
		score += 3
		anchors++
		reasons = append(reasons, "assets/thread_silent.dat encrypted blob (Prestige-style)")
	}
	if hasDevJnic {
		score += 2
		anchors++
		reasons = append(reasons, "dev/jnic/ loader layer")
	}
	if hasCfg {
		score += 1
		reasons = append(reasons, "cfg.json buyer-UUID file")
	}

	if hasNonASCIIEntrypoint(fabricData) {
		score += 2
		reasons = append(reasons, "non-ASCII (mangled) Fabric entrypoint")
	}
	if hasNonASCIIManifestMainClass(zr) {
		score += 1
		reasons = append(reasons, "non-ASCII (mangled) manifest Main-Class")
	}

	strongHits := map[string]bool{}
	supportHits := map[string]bool{}
	for _, e := range zr.File {
		if !strings.HasSuffix(e.Name, ".class") || e.UncompressedSize64 > 2<<20 || e.UncompressedSize64 == 0 {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 2<<20))
		rc.Close()
		for _, m := range weedhackStrong {
			if bytes.Contains(data, []byte(m)) {
				strongHits[m] = true
			}
		}
		if len(supportHits) < len(weedhackSupport) {
			for _, m := range weedhackSupport {
				if bytes.Contains(data, []byte(m)) {
					supportHits[m] = true
				}
			}
		}
	}
	strongCapped := 0
	for k := range strongHits {
		if strongCapped < 3 {
			score += 2
			strongCapped++
		}
		_ = k
	}
	if len(strongHits) > 0 {
		names := make([]string, 0, len(strongHits))
		for k := range strongHits {
			names = append(names, strconv_k(k))
		}
		sort.Strings(names)
		reasons = append(reasons, "operator pivots: "+strings.Join(names, ", "))
	}
	supportCapped := 0
	for range supportHits {
		if supportCapped < 3 {
			score += 1
			supportCapped++
		}
	}
	if len(supportHits) > 0 {
		names := make([]string, 0, len(supportHits))
		for k := range supportHits {
			names = append(names, k)
		}
		sort.Strings(names)
		reasons = append(reasons, "support markers: "+strings.Join(names, ", "))
	}

	if anchors == 0 && len(strongHits) < 2 {
		f.Score = 0
		f.Verdict = "clean"
		f.Reasons = nil
		return f
	}
	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 6:
		f.Verdict = "CONFIRMED"
	case score >= 3:
		f.Verdict = "SUSPICIOUS"
	default:
		f.Verdict = "clean"
	}

	if f.Verdict != "CONFIRMED" {
		convict := 0
		for k := range strongHits {
			if k != "getText" {
				convict++
			}
		}
		if convict >= 2 {
			f.Verdict = "CONFIRMED"
			f.Reasons = append(f.Reasons, "conviction: 2+ operator-unique pivots")
		}
	}
	return f
}

func hasNonASCIIManifestMainClass(zr *zip.ReadCloser) bool {
	for _, e := range zr.File {
		if e.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			return false
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 2048))
		rc.Close()
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Main-Class:") {
				for _, r := range line {
					if r > 127 {
						return true
					}
				}
			}
		}
		return false
	}
	return false
}

func hasNonASCIIEntrypoint(fabricData []byte) bool {
	if len(fabricData) == 0 {
		return false
	}
	s := string(fabricData)

	idx := strings.Index(s, "entrypoints")
	if idx < 0 {
		return false
	}
	for _, r := range s[idx:] {
		if r > 127 {
			return true
		}
		if r == '}' && len(s[idx:]) > 2000 {
			break
		}
	}
	return false
}

var wxsStrong = []string{
	"wxsgrabber-persistence",
	"X-WXS-Build-Token",
	"FabricRuntimeInit",
	"FabricListenerInit",
	".sys-cache",
	"api.x-grabber.com",
	"wxsgrabber-default-rtdb",
	"firebasedatabase",
}

var wxsSupport = []string{
	"PK11SDR_Decrypt",
	"NSS_Init",
	"aHR0cHM6Ly9hcGkueC1ncmFiYmVyLmNvbQ==",
	"d3NjcmlwdC5leGU=",
	"cG93ZXJzaGVsbC5leGU=",
	"Krypton Client.jar",
	"listener.ps1",
	"restorer",
}

func scoreWXSJar(path string) finding {
	f := finding{Path: path, Kind: "jar-wxsgrabber", Family: "wxsgrabber", Verdict: "clean", YaraRules: yaraRulesByFamily["wxsgrabber"]}
	st, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Size = st.Size()
	if h, err := sha256File(path); err == nil {
		f.SHA256 = h
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		f.Verdict = "clean"
		f.Reasons = append(f.Reasons, "not a readable zip")
		return f
	}
	defer zr.Close()

	score := 0
	anchors := 0
	var reasons []string
	var fabricData []byte
	hasLic := false
	hasImpl := false
	nestedLibs := 0
	for _, e := range zr.File {
		switch e.Name {
		case "LICENSE_wxsgrabber-mod":
			hasLic = true
		case "fabric.mod.json":
			if rc, err := e.Open(); err == nil {
				fabricData, _ = io.ReadAll(io.LimitReader(rc, 8192))
				rc.Close()
			}
		}
		if strings.Contains(e.Name, "net/fabricmc/core/impl/") {
			hasImpl = true
		}
		lower := strings.ToLower(e.Name)
		if strings.Contains(lower, "jna") && strings.HasSuffix(lower, ".jar") {
			nestedLibs++
		}
		if strings.Contains(lower, "sqlite-jdbc") {
			nestedLibs++
		}
	}
	if hasLic {
		score += 4
		anchors++
		reasons = append(reasons, "LICENSE_wxsgrabber-mod (unique to WXSGrabber)")
	}
	if hasImpl {
		score += 3
		anchors++
		reasons = append(reasons, "net.fabricmc.core.impl entrypoint (masquerades as Fabric internals)")
	}
	if len(fabricData) > 0 && strings.Contains(string(fabricData), "my-mod") {
		score += 1
		reasons = append(reasons, "fabric mod id my-mod")
	}
	if nestedLibs > 0 {
		score += 1
		reasons = append(reasons, "bundled JNA/SQLite data-theft libs")
	}
	strongHits := map[string]bool{}
	supportHits := map[string]bool{}
	for _, e := range zr.File {
		if !(strings.HasSuffix(e.Name, ".class") || strings.HasSuffix(e.Name, ".ps1") || strings.HasSuffix(e.Name, ".json")) {
			continue
		}
		if e.UncompressedSize64 > 2<<20 || e.UncompressedSize64 == 0 {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 2<<20))
		rc.Close()
		for _, m := range wxsStrong {
			if bytes.Contains(data, []byte(m)) {
				strongHits[m] = true
			}
		}
		for _, m := range wxsSupport {
			if bytes.Contains(data, []byte(m)) {
				supportHits[m] = true
			}
		}
	}
	n := 0
	for range strongHits {
		if n < 4 {
			score += 2
			n++
		}
	}
	if len(strongHits) > 0 {
		names := make([]string, 0, len(strongHits))
		for k := range strongHits {
			names = append(names, strconv_k(k))
		}
		sort.Strings(names)
		reasons = append(reasons, "WXS markers: "+strings.Join(names, ", "))
	}
	n = 0
	for range supportHits {
		if n < 2 {
			score += 1
			n++
		}
	}
	if len(supportHits) > 0 {
		names := make([]string, 0, len(supportHits))
		for k := range supportHits {
			names = append(names, strconv_k(k))
		}
		sort.Strings(names)
		reasons = append(reasons, "support: "+strings.Join(names, ", "))
	}

	if anchors == 0 && len(strongHits) < 3 {
		f.Score = 0
		f.Verdict = "clean"
		f.Reasons = nil
		return f
	}
	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 7:
		f.Verdict = "CONFIRMED"
	case score >= 4:
		f.Verdict = "SUSPICIOUS"
	default:
		f.Verdict = "clean"
	}

	if f.Verdict != "CONFIRMED" {
		convict := 0
		for k := range strongHits {
			if k != "firebasedatabase" {
				convict++
			}
		}
		if convict >= 2 {
			f.Verdict = "CONFIRMED"
			f.Reasons = append(f.Reasons, "conviction: 2+ WXS-unique pivots")
		}
	}
	return f
}

var donkiEntries = []string{
	"com/example/Main.class",
	"com/example/util/ABEPayloadReal.class",
	"com/example/util/DllInjectionHelper.class",
	"com/example/util/HandleDuplicator.class",
	"com/example/util/ProcessHelper.class",
	"com/example/util/CryptoHelper.class",
	"com/example/util/RPCHelper.class",
	"com/example/util/StagingHelper.class",
	"com/example/handlers/browser/BrowserHandler.class",
	"com/example/handlers/discord/DiscordHandler.class",
	"com/example/handlers/files/FileHandler.class",
	"com/example/logging/LoggingManager.class",
	"com/example/handlers/WHandler.class",
}

var donkiLibs = []string{
	"net/querz/mca/MCAFile.class",
	"net/querz/nbt/tag/CompoundTag.class",
	"com/sun/jna/win32-x86-64/jnidispatch.dll",
	"okhttp3/OkHttpClient.class",
}

var donkiStrong = []string{
	"0x9044f5762e43b23ba91d124b51a045f1b51da652",
	"0x1f1bd692",
	"/api/receive",
	"/files/jar/security",
	"/api/static/index.js",
	"Initializing Donki",
	"donki_staging",
	"SecurityManager.jar",
	"dev.majanito.security.Main",
	"abe_decrypt_",
	"app_bound_encrypted_key",
	"donkiFileInfos",
	"X-Tracking-ID",
}

var donkiSupport = []string{
	"minecraftInfo",
	"discordTokens",
	"browserData",
	"logUuid",
	"dQw4w9WgXcQ:",
	"[GRIND] entering",
	"[ROLL] packing",
	"[BLAZED] sent",
	"{708860E0-F641-4611-8895-7D867DD3675B}",
	"{1FCBE96C-1697-43AF-9140-2897C7C69767}",
	"nkbihfbeogaeaoehlefnkodbefgpgknn",
	"SELECT origin_url, username_value, password_value FROM logins",
	"SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies",
	"SELECT username, uuid, access_token, refresh_token, expires FROM minecraft_users",
	"discord.com/api/v9/users/@me",
	"discord_desktop_core",
	"SecurityUpdates",
	"sqlite-jdbc-3.23.1.jar",
	"eth_call",
	"systemInfo",
}

func scoreDonkiJar(path string) finding {
	f := finding{Path: path, Kind: "jar-donki", Family: "donki", Verdict: "clean", YaraRules: yaraRulesByFamily["donki"]}
	st, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Size = st.Size()
	if h, err := sha256File(path); err == nil {
		f.SHA256 = h

		if strings.EqualFold(h, donkiModuleSHA256) {
			f.Score = 10
			f.Verdict = "CONFIRMED"
			f.Reasons = []string{"SHA256 matches curated Donki Module.jar (6770148 B)", "com/example infostealer + ABE bypass; see Module_writeup.md"}
			return f
		}
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		f.Verdict = "clean"
		f.Reasons = append(f.Reasons, "not a readable zip")
		return f
	}
	defer zr.Close()

	names := map[string]bool{}
	for _, e := range zr.File {
		names[e.Name] = true
	}
	entryHits := 0
	for _, n := range donkiEntries {
		if names[n] {
			entryHits++
		}
	}
	libHits := 0
	for _, n := range donkiLibs {
		if names[n] {
			libHits++
		}
	}
	hasManifestDonki := false
	hasManifestStage2 := false
	for _, e := range zr.File {
		if e.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 4096))
		rc.Close()
		if bytes.Contains(data, []byte("Main-Class: com.example.Main")) {
			hasManifestDonki = true
		}
		if bytes.Contains(data, []byte(donkiStage2Main)) {
			hasManifestStage2 = true
		}
		break
	}

	score := 0
	anchors := 0
	var reasons []string
	if entryHits >= 6 {
		score += 3
		anchors++
		reasons = append(reasons, fmt.Sprintf("%d/13 Donki com/example stealer entries (JNIC-resistant)", entryHits))
	} else if entryHits >= 3 {
		score += 2
		anchors++
		reasons = append(reasons, fmt.Sprintf("%d/13 Donki com/example stealer entries", entryHits))
	} else if entryHits >= 1 {
		score += 1
		reasons = append(reasons, fmt.Sprintf("%d Donki entry (weak alone — needs pivots)", entryHits))
	}
	if libHits >= 2 && entryHits >= 2 {
		score += 2
		anchors++
		reasons = append(reasons, fmt.Sprintf("querz/JNA/okhttp lib combo (%d libs + %d entries)", libHits, entryHits))
	} else if libHits >= 3 {
		score += 1
		reasons = append(reasons, "querz/JNA/okhttp lib combo (weak alone)")
	}
	if hasManifestDonki && entryHits >= 3 {
		score += 2
		anchors++
		reasons = append(reasons, "manifest Main-Class: com.example.Main + stealer entries")
	} else if hasManifestDonki && entryHits >= 1 {
		score += 1
		reasons = append(reasons, "manifest Main-Class: com.example.Main")
	}
	if hasManifestStage2 {
		score += 3
		anchors++
		reasons = append(reasons, "manifest Main-Class: dev.majanito.security.Main (Donki stage-2)")
	}

	if strings.EqualFold(filepath.Base(path), "SecurityManager.jar") {
		score += 1
		reasons = append(reasons, "filename SecurityManager.jar (Donki stage-2 name)")
	}

	strongHits := map[string]bool{}
	supportHits := map[string]bool{}
	for _, e := range zr.File {
		if !strings.HasSuffix(e.Name, ".class") || e.UncompressedSize64 > 2<<20 || e.UncompressedSize64 == 0 {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 2<<20))
		rc.Close()
		for _, m := range donkiStrong {
			if bytes.Contains(data, []byte(m)) {
				strongHits[m] = true
			}
		}
		if len(supportHits) < len(donkiSupport) {
			for _, m := range donkiSupport {
				if bytes.Contains(data, []byte(m)) {
					supportHits[m] = true
				}
			}
		}
	}
	n := 0
	for range strongHits {
		if n < 4 {
			score += 2
			n++
		}
	}
	if len(strongHits) > 0 {
		snames := make([]string, 0, len(strongHits))
		for k := range strongHits {
			snames = append(snames, strconv_k(k))
		}
		sort.Strings(snames)
		reasons = append(reasons, "Donki pivots: "+strings.Join(snames, ", "))
	}
	n = 0
	for range supportHits {
		if n < 3 {
			score += 1
			n++
		}
	}
	if len(supportHits) > 0 {
		snames := make([]string, 0, len(supportHits))
		for k := range supportHits {
			snames = append(snames, strconv_k(k))
		}
		sort.Strings(snames)
		reasons = append(reasons, "support: "+strings.Join(snames, ", "))
	}

	if anchors == 0 && len(strongHits) < 2 {
		f.Score = 0
		f.Verdict = "clean"
		f.Reasons = nil
		return f
	}
	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 7:
		f.Verdict = "CONFIRMED"
	case score >= 4:
		f.Verdict = "SUSPICIOUS"
	default:
		f.Verdict = "clean"
	}

	if f.Verdict != "CONFIRMED" {
		_, hasContract := strongHits["0x9044f5762e43b23ba91d124b51a045f1b51da652"]
		unique := 0
		for k := range strongHits {
			switch k {
			case "0x1f1bd692", "/api/receive", "/files/jar/security", "/api/static/index.js",
				"Initializing Donki", "donki_staging", "SecurityManager.jar",
				"dev.majanito.security.Main", "abe_decrypt_", "app_bound_encrypted_key",
				"donkiFileInfos", "X-Tracking-ID":
				unique++
			}
		}
		if (hasContract && len(strongHits) >= 2) || unique >= 2 {
			f.Verdict = "CONFIRMED"
			f.Reasons = append(f.Reasons, "conviction: 2+ Donki-unique pivots")
		}
	}
	return f
}

func scoreJarAll(path string) finding {
	cands := []finding{scoreJar(path), scoreWeedHackJar(path), scoreWXSJar(path), scoreDonkiJar(path), scoreGenericJar(path)}
	best := cands[0]
	bestRank := verdictRank(best.Verdict)
	for _, c := range cands[1:] {
		if r := verdictRank(c.Verdict); r > bestRank || (r == bestRank && c.Score > best.Score) {
			best = c
			bestRank = r
		}
	}

	if best.Verdict == "clean" {
		for _, c := range cands {
			if len(c.Reasons) == 1 && c.Reasons[0] == "not a readable zip" {
				best.Reasons = c.Reasons
				break
			}
		}
	}
	return best
}

func verdictRank(v string) int {
	switch v {
	case "CONFIRMED":
		return 2
	case "SUSPICIOUS":
		return 1
	default:
		return 0
	}
}

type hashEntry struct {
	SHA     string
	Name    string
	Kind    string
	Family  string
	Verdict string
	Note    string
}

var destructiveBySize = map[int64][]hashEntry{
	3514368: {{"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry ransomware dropper", "hash-destructive", "destructive", "CONFIRMED", "WannaCry; also remove service mssecsvc2.0; restore from backup, do NOT pay"}},
	362360: {{"027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", "NotPetya wiper", "hash-destructive", "destructive", "CONFIRMED", "NotPetya destroys MBR; re-image from backup. C:\\Windows\\perfc present = vaccinated"}},
	517632: {{"743e16b3ef4d39fc11c5e8ec890dcd29f034a6eca51be4f7fca6e23e60dbd7a1", "Stuxnet dropper", "hash-destructive", "destructive", "CONFIRMED", "Stuxnet LNK worm; also remove MRXCLS/MRXNET drivers"}},
	26616: {{"1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c", "Stuxnet MRXCLS.sys driver", "hash-destructive", "destructive", "CONFIRMED", "Stuxnet signed driver"}},
	17400: {{"0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198", "Stuxnet MRXNET.sys driver", "hash-destructive", "destructive", "CONFIRMED", "Stuxnet signed driver"}},
	25720: {{"70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b", "Stuxnet DLL", "hash-destructive", "destructive", "CONFIRMED", "Stuxnet component"}},
	54569: {{"e79f164ccc75a5d5c032b4c5a96d6ad7604faffb28afe77bc29b9173fa3543e4", "Krotten (curated sample)", "known-sample", "known-sample", "CONFIRMED", "SHA256 matches curated C:\\MALWARE sample; family uncharacterized"}},
	47616: {{"eae9771e2eeb7ea3c6059485da39e77b8c0c369232f01334954fbac1c186c998", "Mimikatz x86 (NotPetya bundle)", "hacktool", "hacktool", "SUSPICIOUS", "dual-use credential tool; verify before removing"}},
	56320: {{"02ef73bd2458627ed7b397ec26ee2de2e92c71a0e7588f78734761d8edbdcd9f", "Mimikatz x64 (NotPetya bundle)", "hacktool", "hacktool", "SUSPICIOUS", "dual-use credential tool; verify before removing"}},
	4861: {{"5fa9feff9be14b2e1751af3b3d9bde042d52785cd445b1a14994b5b79f21e577", "NotPetya payload_4", "known-sample", "known-sample", "SUSPICIOUS", "uncharacterized bundle payload"}},
	381816: {{"f8dbabdfa03068130c277ce49c60e35c029ff29d9e3c74c362521f3fb02670d5", "PsExec (NotPetya bundle)", "hacktool", "hacktool", "SUSPICIOUS", "dual-use admin tool; verify before removing"}},
}

func checkFileHash(path string) finding {
	f := finding{Verdict: "clean"}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return f
	}
	cands, ok := destructiveBySize[st.Size()]
	if !ok {
		return f
	}
	sum, err := sha256File(path)
	if err != nil {
		return f
	}
	for _, c := range cands {
		if strings.EqualFold(sum, c.SHA) {
			return finding{
				Path: path, Kind: c.Kind, Family: c.Family,
				Score: 10, Verdict: c.Verdict,
				Reasons: []string{"SHA256 " + sum[:16] + "... matches curated sample: " + c.Name, c.Note},
				SHA256: sum, Size: st.Size(),
			}
		}
	}
	return f
}

func isSilentNetFabric(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	s := string(data)

	idPkg := strings.Contains(s, `"id"`) && (strings.Contains(s, `"package"`) || strings.Contains(s, `"sample"`))
	entry := strings.Contains(s, "com.github.")
	icon := strings.Contains(s, "assets/package/icon.png")
	if idPkg && entry && icon {
		return true
	}

	nospace := strings.ReplaceAll(s, " ", "")
	if strings.Contains(nospace, `"id":"package"`) || strings.Contains(nospace, `"id":"sample"`) {
		if strings.Contains(s, "com.github.") {
			return true
		}
	}
	return false
}

func scoreRawFamily(path string) finding {
	f := finding{Path: path, Kind: "exe-variant", Verdict: "clean"}
	st, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Size = st.Size()
	if f.Size > 100<<20 {
		f.Reasons = append(f.Reasons, "skipped: >100MB")
		return f
	}
	if h, err := sha256File(path); err == nil {
		f.SHA256 = h
	} else {
		f.Reasons = append(f.Reasons, "unreadable: "+err.Error())
		f.Verdict = "clean"
		return f
	}
	fh, err := os.Open(path)
	if err != nil {
		return f
	}
	defer fh.Close()

	const preRead = 2 << 20
	head, _ := io.ReadAll(io.LimitReader(fh, preRead))
	lowerHead := bytes.ToLower(head)
	hasPrefilter := bytes.Contains(head, []byte("NtProfile")) ||
		bytes.Contains(lowerHead, []byte("ntprofile")) ||
		bytes.Contains(head, []byte("AppHost")) ||
		bytes.Contains(head, []byte("apphost")) ||
		bytes.Contains(head, []byte("spec_from_file_location")) ||
		bytes.Contains(head, []byte("donki")) ||
		bytes.Contains(lowerHead, []byte("donki")) ||
		bytes.Contains(head, []byte("abe_decrypt_")) ||
		bytes.Contains(head, []byte("SecurityManager")) ||
		bytes.Contains(head, []byte("majanito")) ||
		bytes.Contains(lowerHead, []byte("majanito")) ||
		bytes.Contains(head, []byte("0x9044")) ||
		bytes.Contains(head, []byte("X-Tracking-ID")) ||
		bytes.Contains(head, []byte("discord_desktop_core")) ||
		bytes.Contains(head, []byte("app_bound_encrypted_key")) ||
		bytes.Contains(head, []byte("dQw4w9WgXcQ")) ||
		bytes.Contains(head, []byte("/api/receive"))
	if !hasPrefilter && !strings.HasSuffix(strings.ToLower(path), "main.py") && !strings.Contains(strings.ToLower(path), "index.js") {

		lowerPath := strings.ToLower(path)
		isPE := strings.HasSuffix(lowerPath, ".exe") || strings.HasSuffix(lowerPath, ".dll")
		if isPE || f.Size > 8<<20 {
			f.Score = 0
			f.Verdict = "clean"
			return f
		}
	}

	var data []byte
	if int64(len(head)) >= f.Size || int64(len(head)) >= preRead {

		rest, _ := io.ReadAll(io.LimitReader(fh, (16<<20)-int64(len(head))))
		data = append(head, rest...)
	} else {
		data = head
	}

	markers := append(append([]string{}, embeddedCleanMarkers...), embeddedStage2Markers...)
	markers = append(markers, weedhackStrong...)
	markers = append(markers, weedhackSupport...)
	markers = append(markers, wxsStrong...)
	markers = append(markers, donkiStrong...)
	markers = append(markers, donkiSupport...)

	markers = append(markers, yaraLiterals...)

	hits := map[string]bool{}
	lower := bytes.ToLower(data)
	for _, m := range markers {
		if m == "" || len(m) < 4 {
			continue
		}
		if bytes.Contains(data, []byte(m)) || bytes.Contains(lower, bytes.ToLower([]byte(m))) {
			hits[m] = true
		} else {

			w := utf16LE(m)
			if len(w) > 0 && bytes.Contains(data, w) {
				hits[m] = true
			}
		}
	}

	score := 0
	var reasons []string
	hasStaging := hits["NtProfileIndex"]
	nPlain := len(hits)
	if hasStaging {
		score += 4
		reasons = append(reasons, "NtProfileIndex staging marker")
	}

	support := 0
	for _, k := range []string{"_spawn.log", "-restarted", "AppHost", "main.py", "python.exe", "jre-embedded", "X-Runtime-Env", "NtProfileSync", "/shard/submitData", "/cdn/e/", fernetKey, contractAddress, "LOCALAPPDATA"} {
		if hits[k] {
			support++
		}
	}
	weedSupport := 0
	for _, k := range append(append([]string{}, weedhackStrong...), weedhackSupport...) {
		if hits[k] {
			weedSupport++
		}
	}
	donkiSupportN := 0
	for _, k := range append(append([]string{}, donkiStrong...), donkiSupport...) {
		if hits[k] {
			donkiSupportN++
		}
	}

	donkiUnique := 0
	for _, k := range []string{donkiContract, donkiSelector, "/api/receive", "/files/jar/security", "/api/static/index.js", "Initializing Donki", "donki_staging", "SecurityManager.jar", donkiStage2Main, "abe_decrypt_", "app_bound_encrypted_key", "donkiFileInfos", "X-Tracking-ID", "dQw4w9WgXcQ:", "{708860E0-F641-4611-8895-7D867DD3675B}", "{1FCBE96C-1697-43AF-9140-2897C7C69767}", "nkbihfbeogaeaoehlefnkodbefgpgknn", "discord.com/api/v9/users/@me", "discord_desktop_core"} {
		if hits[k] {
			donkiUnique++
		}
	}
	if donkiUnique == 0 {
		donkiSupportN = 0
	}
	score += support + weedSupport + donkiSupportN
	if support > 0 {
		names := []string{}
		for _, k := range []string{"_spawn.log", "-restarted", "AppHost", "main.py", "python.exe", "jre-embedded", "X-Runtime-Env", "NtProfileSync", "/shard/submitData", "/cdn/e/", "LOCALAPPDATA"} {
			if hits[k] {
				names = append(names, k)
			}
		}
		if hits[fernetKey] {
			names = append(names, "hardcoded Fernet key")
		}
		if hits[contractAddress] {
			names = append(names, "Polygon C2 contract")
		}
		reasons = append(reasons, "markers: "+strings.Join(names, ", "))
	}
	if weedSupport > 0 {
		names := []string{}
		for _, k := range append(append([]string{}, weedhackStrong...), weedhackSupport...) {
			if hits[k] {
				names = append(names, strconv_k(k))
			}
		}
		sort.Strings(names)
		reasons = append(reasons, "WeedHack markers: "+strings.Join(names, ", "))
	}
	if donkiSupportN > 0 {
		names := []string{}
		for _, k := range append(append([]string{}, donkiStrong...), donkiSupport...) {
			if hits[k] {
				names = append(names, strconv_k(k))
			}
		}
		sort.Strings(names)
		reasons = append(reasons, "Donki markers: "+strings.Join(names, ", "))
	}

	if strings.HasSuffix(strings.ToLower(path), "main.py") && f.SHA256 == mainPySHA256 {
		score += 6
		reasons = append(reasons, "exact AppHost/main.py hash match")
		f.Kind = "stage2-file"
		f.Family = "silentnet"
		f.YaraRules = yaraRulesByFamily["silentnet"]
	}
	_ = nPlain

	if f.Kind == "exe-variant" || f.Kind == "" {
		switch {
		case donkiSupportN > support && donkiSupportN > weedSupport && donkiSupportN > 0:
			f.Family = "donki"
			f.YaraRules = yaraRulesByFamily["donki"]
		case weedSupport > support && weedSupport > 0:
			f.Family = "weedhack"
			f.YaraRules = yaraRulesByFamily["weedhack"]
		case support > 0 || hasStaging:
			f.Family = "silentnet"
			f.YaraRules = yaraRulesByFamily["silentnet"]
		}
		if f.Kind == "" {
			f.Kind = "exe-variant"
		}
	}

	lowerPath := strings.ToLower(path)
	isPE := strings.HasSuffix(lowerPath, ".exe") || strings.HasSuffix(lowerPath, ".dll")
	if isPE {
		if !(hasStaging && support >= 1) && support < 3 && weedSupport < 3 && donkiSupportN < 3 {
			f.Score = 0
			f.Verdict = "clean"
			f.Reasons = reasons
			f.Family = ""
			return f
		}
	} else {
		if support+weedSupport+donkiSupportN < 3 && score < 6 {
			f.Score = 0
			f.Verdict = "clean"
			f.Reasons = reasons
			f.Family = ""
			return f
		}
	}

	f.Score = score
	f.Reasons = reasons
	switch {
	case score >= 6:
		f.Verdict = "CONFIRMED"
		if f.Kind == "" {
			f.Kind = "exe-variant"
		}
	case score >= 3:
		f.Verdict = "SUSPICIOUS"
	default:
		f.Verdict = "clean"
	}
	return f
}

func utf16LE(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			continue
		}
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

type gameLauncher struct {
	Name  string
	Paths []string
}

func knownGameLaunchers() []gameLauncher {
	return []gameLauncher{
		{"Vanilla Minecraft", []string{`%APPDATA%\.minecraft`}},
		{"PrismLauncher", []string{`%APPDATA%\PrismLauncher\instances`}},
		{"PolyMC", []string{`%APPDATA%\PolyMC\instances`}},
		{"MultiMC", []string{`%APPDATA%\MultiMC\instances`}},
		{"ATLauncher", []string{`%APPDATA%\ATLauncher\Instances`}},
		{"Technic", []string{`%APPDATA%\.technic\modpacks`}},
		{"FTB App", []string{`%LOCALAPPDATA%\.ftba\instances`}},
		{"FTB Legacy", []string{`%APPDATA%\ftblauncher\ModPacks`}},
		{"CurseForge", []string{
			`%USERPROFILE%\curseforge\minecraft\Instances`,
			`%USERPROFILE%\Documents\Curse\Minecraft\Instances`,
			`%USERPROFILE%\Twitch\Minecraft\Instances`,
			`%USERPROFILE%\Documents\Twitch\Minecraft\Instances`,
		}},
		{"GDLauncher", []string{`%APPDATA%\gdlauncher_next\instances`, `%APPDATA%\.gdlauncher\instances`}},
		{"Modrinth App", []string{`%APPDATA%\ModrinthApp\profiles`, `%APPDATA%\ModrinthApp`}},
		{"Badlion", []string{`%APPDATA%\.badlion`}},
		{"Lunar", []string{`%USERPROFILE%\.lunarclient`}},
		{"Feather", []string{`%APPDATA%\.feather`, `%APPDATA%\.minecraft\feather`}},

		{"Dawn", []string{`%APPDATA%\.dawn`, `%APPDATA%\Dawn`, `%APPDATA%\dawnmc`, `%APPDATA%\.dawnmc`, `%USERPROFILE%\.dawn`}},
		{"TLauncher", []string{`%APPDATA%\.tlauncher\legacy\Minecraft\game`}},
		{"XMCL", []string{`%APPDATA%\xmcl`}},
	}
}

func detectGameLaunchers() []string {
	var found []string
	for _, l := range knownGameLaunchers() {
		for _, p := range l.Paths {
			if dirExists(expandPathEnv(p)) {
				found = append(found, l.Name)
				break
			}
		}
	}
	return found
}

func defaultScanRoots(full bool) []string {

	if *fRoots != "" {
		roots := []string{}
		for _, p := range strings.Split(*fRoots, ",") {
			p = strings.TrimSpace(strings.Trim(p, `"`))
			if p != "" {
				roots = append(roots, p)
			}
		}
		if *fExtraPath != "" {
			for _, p := range strings.Split(*fExtraPath, ",") {
				p = strings.TrimSpace(strings.Trim(p, `"`))
				if p != "" {
					roots = append(roots, p)
				}
			}
		}
		return dedupeRoots(roots)
	}
	u := os.Getenv("USERPROFILE")
	appdata := os.Getenv("APPDATA")
	localapp := os.Getenv("LOCALAPPDATA")
	temp := os.Getenv("TEMP")
	tmp := os.Getenv("TMP")
	pub := os.Getenv("PUBLIC")
	progdata := os.Getenv("PROGRAMDATA")
	if progdata == "" {
		progdata = `C:\ProgramData`
	}
	roots := []string{
		filepath.Join(u, "Downloads"),
		filepath.Join(u, "Desktop"),
		filepath.Join(u, "Documents"),
	}

	for _, l := range knownGameLaunchers() {
		roots = append(roots, l.Paths...)
	}
	roots = append(roots,
		temp, tmp,
		filepath.Join(localapp, "Temp"),
		filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(progdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		stagingDir(),
	)
	if full {

		roots = append(roots,
			`C:\Users`,
			progdata,
			filepath.Join(pub, "Desktop"),
			filepath.Join(pub, "Downloads"),
		)
	}

	if *fExtraPath != "" {
		for _, p := range strings.Split(*fExtraPath, ",") {
			p = strings.TrimSpace(strings.Trim(p, `"`))
			if p != "" {
				roots = append(roots, p)
			}
		}
	}

	return dedupeRoots(roots)
}

func dedupeRoots(roots []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		r = expandPathEnv(r)
		r = filepath.Clean(r)
		key := strings.ToLower(r)
		if seen[key] {
			continue
		}
		seen[key] = true
		if dirExists(r) {
			out = append(out, r)
		} else if exists(r) {
			out = append(out, r)
		} else {
			vlogf("scan root missing, skipping: %s", r)
		}
	}
	return out
}

var skipDirNames = map[string]bool{
	"windows": true, "$recycle.bin": true, "system volume information": true,
	"$windows.~bt": true, "$windows.~ws": true, "node_modules": true, ".git": true,

	"libraries": true, "assets": true, "saves": true, "config": true, "logs": true,
	"crash-reports": true, "resourcepacks": true, "shaderpacks": true,
	".fabric": true, "processedmods": true, "natives": true, "runtime": true,
}

func shouldSkipDir(path string) bool {
	lp := strings.ToLower(path)

	if strings.HasPrefix(lp, `c:\windows`) {
		return true
	}
	if strings.HasPrefix(lp, `c:\program files`) {
		return true
	}

	if strings.Contains(lp, "mrt"+string(filepath.Separator)+"quarantine") {
		return true
	}
	if strings.Contains(lp, "silentnetremover"+string(filepath.Separator)+"quarantine") {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	if skipDirNames[base] {
		return true
	}
	return false
}

func collectCandidates(roots []string) []string {
	var files []string
	seenFiles := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	selfExe := ""
	if exe, err := os.Executable(); err == nil {
		selfExe = strings.ToLower(exe)

	}

	addFile := func(p string) {
		if selfExe != "" && strings.ToLower(p) == selfExe {
			return
		}

		key := strings.ToLower(p)
		mu.Lock()
		if !seenFiles[key] {
			seenFiles[key] = true
			files = append(files, p)
		}
		mu.Unlock()
	}

	for _, r := range roots {
		if !exists(r) {
			continue
		}
		st, err := os.Stat(r)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			addFile(r)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(root string) {
			defer wg.Done()
			defer func() { <-sem }()
			filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if p != root && shouldSkipDir(p) {
						vlogf("skipping dir: %s", p)
						return filepath.SkipDir
					}
					return nil
				}
				ext := strings.ToLower(filepath.Ext(p))

				if info, err := d.Info(); err == nil {
					sz := info.Size()
					if sz == 0 {
						return nil
					}
					switch ext {
					case ".exe", ".dll":
						if sz > 60<<20 {
							return nil
						}
					case ".jar", ".zip":
						if sz > 40<<20 {
							return nil
						}
					default:
						if sz > 40<<20 {
							return nil
						}
					}
				}
				switch ext {
				case ".jar", ".zip", ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".infected":
					addFile(p)
				default:

					lp := strings.ToLower(p)
					if strings.HasSuffix(lp, ".meta") || strings.HasSuffix(lp, ".sha1") || strings.HasSuffix(lp, ".sha256") || strings.HasSuffix(lp, ".txt") {
						return nil
					}
					if ext == ".py" && strings.Contains(lp, "apphost") {
						addFile(p)
						return nil
					}
					if strings.Contains(lp, ".jar.") || strings.HasSuffix(lp, ".jar_") {
						addFile(p)
					}
				}
				return nil
			})
		}(r)
	}
	wg.Wait()
	return files
}

func scanFiles(files []string) []finding {
	yaraBin := externalYara()

	nRules := len(yaraRulesByFamily)
	if yaraBin != "" && nRules > 0 {
		logf("[yara] external binary found (%s); internal scores confirmed against %d rule file(s)", yaraBin, nRules)
	} else if nRules > 0 {
		logf("[yara] using embedded engine with literals from %d rule file(s)", nRules)
	} else {
		logf("[yara] using embedded engine with built-in literals")
	}

	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 4 {
		numWorkers = 4
	}
	if numWorkers > 16 {
		numWorkers = 16
	}
	jobs := make(chan string, len(files))
	results := make(chan finding, len(files))
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {

				if hf := checkFileHash(p); hf.Verdict == "CONFIRMED" || hf.Verdict == "SUSPICIOUS" {
					results <- hf
					continue
				}
				var f finding
				ext := strings.ToLower(filepath.Ext(p))
				lp := strings.ToLower(p)
				isJarLike := ext == ".jar" || ext == ".zip" || strings.Contains(lp, ".jar.")
				if isJarLike {
					f = scoreJarAll(p)

					if len(f.Reasons) == 1 && f.Reasons[0] == "not a readable zip" {
						if r := scoreRaw(p); r.Verdict != "clean" {
							f = r
						}
					}
				} else {
					f = scoreRaw(p)
				}
				if f.Verdict != "clean" && yaraBin != "" && f.YaraRules != "" {
					f.YaraHits = confirmWithExternalYara(yaraBin, f.YaraRules, p)
				}
				results <- f
			}
		}()
	}
	for _, p := range files {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)

	var out []finding
	for f := range results {
		if f.Verdict != "clean" {
			out = append(out, f)
		} else if *fVerbose {
			vlogf("clean (score %d): %s %v", f.Score, f.Path, f.Reasons)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func pipeExists() bool {

	f, err := os.OpenFile(pipeName, os.O_RDWR, 0600)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

type procInfo struct {
	PID  string
	Exe  string
	Cmd  string
	Name string
}

func listProcesses() []procInfo {

	ps := `Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation`
	out, code := runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if code == 0 && strings.Contains(out, "CommandLine") {
		return parseWmicCSV(out)
	}
	out2, code2 := runCmd("wmic", "process", "get", "ProcessId,ExecutablePath,CommandLine", "/format:csv")
	if code2 == 0 && strings.Contains(out2, "CommandLine") {
		return parseWmicCSV(out2)
	}
	warnf("process listing failed (powershell CIM and wmic both failed)")
	return nil
}

func parseWmicCSV(out string) []procInfo {
	r := csv.NewReader(strings.NewReader(out))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil
	}
	if len(rows) < 2 {
		return nil
	}
	header := rows[0]
	idxNode, idxCmd, idxExe, idxPID := -1, -1, -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "node":
			idxNode = i
		case "commandline":
			idxCmd = i
		case "executablepath":
			idxExe = i
		case "processid":
			idxPID = i
		}
	}
	var procs []procInfo
	for _, row := range rows[1:] {
		get := func(i int) string {
			if i >= 0 && i < len(row) {
				return row[i]
			}
			return ""
		}
		p := procInfo{Exe: get(idxExe), Cmd: get(idxCmd), PID: get(idxPID)}
		_ = idxNode
		if p.PID == "" {
			continue
		}
		if p.Exe != "" {
			p.Name = filepath.Base(p.Exe)
		}
		procs = append(procs, p)
	}
	return procs
}

func isStealerProcess(p procInfo) (bool, string) {
	exe := strings.ToLower(p.Exe)
	cmd := strings.ToLower(p.Cmd)
	joined := exe + " " + cmd
	if strings.Contains(joined, "ntprofileindex") {
		return true, "path/commandline references NtProfileIndex staging dir"
	}
	if strings.Contains(joined, "apphost") && (strings.Contains(joined, "main.py") || strings.Contains(joined, "app.pyd")) {
		return true, "AppHost stealer bundle in command line"
	}
	if strings.Contains(cmd, "-restarted") && (strings.Contains(cmd, "com.github") || strings.Contains(cmd, ".jar")) {
		return true, "stage-1 restart marker (-restarted + com.github/.jar)"
	}

	if strings.Contains(cmd, "--jw") && strings.Contains(cmd, ".jar") {
		return true, "WeedHack re-exec marker (--jw + .jar)"
	}

	if strings.Contains(joined, "dev.majanito.security.main") || strings.Contains(joined, "securitymanager.jar") {
		return true, "Donki stage-2 (SecurityManager.jar / dev.majanito.security.Main)"
	}
	if strings.Contains(cmd, "--dont-elevate") && strings.Contains(cmd, "--add-to-registry") {
		return true, "Donki stage-2 persistence flags (--dont-elevate + --add-to-registry)"
	}
	if strings.Contains(joined, "donki_staging") || strings.Contains(joined, "abe_decrypt_") {
		return true, "Donki staging dir / ABE pipe in command line"
	}

	if strings.Contains(cmd, "com.example.main") && strings.Contains(cmd, ".jar") &&
		(strings.Contains(exe, "java") || strings.Contains(cmd, "javaw") || strings.Contains(cmd, "-jar") || strings.Contains(cmd, "-cp")) {
		return true, "Donki stage-1 entrypoint (com.example.Main + .jar under java)"
	}
	if strings.Contains(joined, "majanito") || strings.Contains(joined, "initializeweedhack") {
		return true, "WeedHack stage-2 class in command line"
	}

	if strings.Contains(joined, ".sys-cache") || strings.Contains(joined, "listener.ps1") || strings.Contains(joined, "restorer.ps1") {
		return true, "WXSGrabber .sys-cache script in command line"
	}

	if exe == "tasksche.exe" || exe == "taskdl.exe" || exe == "wcry.exe" ||
		strings.Contains(exe, "@wanadecryptor@") || strings.Contains(exe, "@wanadecryptor") {
		return true, "WannaCry process image name"
	}
	return false, ""
}

func killProcesses(procs []procInfo, dry bool) int {
	killed := 0
	for _, p := range procs {
		if ok, reason := isStealerProcess(p); ok {
			logf("[kill] PID %s (%s): %s", p.PID, p.Exe, reason)
			if dry {
				continue
			}
			_, code := runCmd("taskkill", "/PID", p.PID, "/F")
			if code == 0 {
				killed++
			} else {
				warnf("taskkill PID %s failed (exit %d); retry after staging delete may be needed", p.PID, code)
			}
		}
	}
	return killed
}

func quarantineFile(path, quarantine string, f finding, dry bool) (string, error) {
	if !*fAllowSampleDir && isSampleCollection(path) {
		return "", fmt.Errorf("refusing to quarantine inside the C:\\MALWARE research collection (re-run with --allow-sample-dir to override)")
	}
	sum := f.SHA256
	if sum == "" {
		if h, err := sha256File(path); err == nil {
			sum = h
		}
	}
	base := filepath.Base(path)
	stamp := time.Now().Format("20060102-150405")
	dest := filepath.Join(quarantine, fmt.Sprintf("%s_%s.quarantined", base, stamp))

	for i := 2; exists(dest) || exists(dest+".json"); i++ {
		dest = filepath.Join(quarantine, fmt.Sprintf("%s_%s_%d.quarantined", base, stamp, i))
	}
	if dry {
		logf("[dry-run] would quarantine %s -> %s", path, dest)
		return dest, nil
	}
	if err := os.MkdirAll(quarantine, 0755); err != nil {
		return "", err
	}

	if err := os.Rename(path, dest); err != nil {
		in, err2 := os.Open(path)
		if err2 != nil {
			return "", err2
		}
		defer in.Close()
		out, err2 := os.Create(dest)
		if err2 != nil {
			return "", err2
		}
		if _, err2 := io.Copy(out, in); err2 != nil {
			out.Close()
			return "", err2
		}
		out.Close()
		in.Close()
		os.Remove(path)
	}
	sidecar := dest + ".json"
	meta := fmt.Sprintf("{\"original_path\":%q,\"sha256\":%q,\"size\":%d,\"verdict\":%q,\"family\":%q,\"kind\":%q,\"score\":%d,\"reasons\":%q,\"yara_hits\":%q,\"quarantined_at\":%q}\n",
		path, sum, f.Size, f.Verdict, f.Family, f.Kind, f.Score,
		strings.Join(f.Reasons, "; "), strings.Join(f.YaraHits, ","), time.Now().UTC().Format(time.RFC3339))
	os.WriteFile(sidecar, []byte(meta), 0644)
	logf("[quarantine] %s -> %s", path, dest)
	return dest, nil
}

func deletePath(path string, dry bool) error {
	if !*fAllowSampleDir && isSampleCollection(path) {
		return fmt.Errorf("refusing to delete inside the C:\\MALWARE research collection (re-run with --allow-sample-dir to override)")
	}
	if dry {
		logf("[dry-run] would delete %s", path)
		return nil
	}

	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			os.Chmod(p, 0700)
		}
		return nil
	})
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	logf("[remove] deleted %s", path)
	return nil
}

func removeStaging(dry bool) bool {
	sd := stagingDir()
	if !exists(sd) {
		logf("[triage] staging dir absent (good): %s", sd)
		return true
	}
	logf("[triage] staging dir PRESENT (infected): %s", sd)

	entries, _ := os.ReadDir(sd)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) > 12 {
		names = append(names[:12], fmt.Sprintf("... +%d more", len(entries)-12))
	}
	logf("         contains: %s", strings.Join(names, ", "))
	if err := deletePath(sd, dry); err != nil {
		warnf("failed to delete staging dir: %v (re-run as admin after killing processes)", err)
		return false
	}
	return !exists(sd)
}

func cleanSpawnLogs(dry bool) int {
	cands := []string{
		filepath.Join(os.Getenv("TEMP"), "_spawn.log"),
		filepath.Join(os.Getenv("TMP"), "_spawn.log"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp", "_spawn.log"),
		filepath.Join(stagingDir(), "_spawn.log"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", "_spawn.log"),
		`C:\Windows\Temp\_spawn.log`,
	}
	n := 0
	seen := map[string]bool{}
	for _, p := range cands {
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		if exists(p) {
			logf("[remove] spawn log: %s", p)
			if dry {
				n++
				continue
			}
			if err := os.Remove(p); err != nil {
				warnf("cannot delete %s: %v", p, err)
			} else {
				n++
			}
		}
	}
	if n == 0 {
		vlogf("no _spawn.log files found")
	}
	return n
}

func cleanWeedHack(dry bool) int {
	n := 0
	for _, dir := range []string{os.Getenv("TEMP"), os.Getenv("TMP"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp")} {
		if dir == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "jvmtp-*.dll"))
		for _, m := range matches {
			logf("[remove] WeedHack native: %s", m)
			if dry {
				n++
				continue
			}
			if err := os.Remove(m); err != nil {
				warnf("cannot delete %s: %v", m, err)
			} else {
				n++
			}
		}
	}
	if n == 0 {
		vlogf("no jvmtp-*.dll files found")
	}
	return n
}

func cleanWXS(dry bool) int {
	n := 0
	dir := filepath.Join(os.Getenv("APPDATA"), ".sys-cache")
	if dirExists(dir) {
		logf("[triage] WXSGrabber staging dir PRESENT: %s", dir)
		if err := deletePath(dir, dry); err != nil {
			warnf("failed to delete %s: %v", dir, err)
		} else {
			n++
		}
	} else {
		vlogf("no .sys-cache dir found")
	}
	runKeys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, key := range runKeys {
		for _, name := range []string{"FabricRuntimeInit", "FabricListenerInit"} {
			if out, code := runCmd("reg", "query", key, "/v", name); code == 0 {
				logf("[registry] WXSGrabber autorun hit: %s -> %s\n%s", key, name, firstLines(out, 4))
				if dry {
					n++
					continue
				}
				if _, c := runCmd("reg", "delete", key, "/v", name, "/f"); c == 0 {
					logf("[registry] deleted value %s in %s", name, key)
					n++
				} else {
					warnf("cannot delete registry value %s in %s (run as admin)", name, key)
				}
			}
		}
	}
	return n
}

func donkiSecurityDir() string {
	return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "SecurityUpdates")
}

func donkiStagingDirs() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range []string{os.Getenv("TEMP"), os.Getenv("TMP"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp")} {
		if d == "" {
			continue
		}
		p := filepath.Join(d, "donki_staging")
		key := strings.ToLower(p)
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

func donkiPipeExists() bool {
	entries, err := os.ReadDir(`\\.\pipe\`)
	if err != nil {
		vlogf("pipe list failed: %v", err)
		return false
	}
	for _, e := range entries {
		if strings.HasPrefix(strings.ToLower(e.Name()), "abe_decrypt_") {
			return true
		}
	}
	return false
}

func cleanDonki(dry bool, quarantine string) int {
	n := 0
	if dir := donkiSecurityDir(); dirExists(dir) {
		logf("[triage] Donki staging dir PRESENT: %s", dir)
		if err := deletePath(dir, dry); err != nil {
			warnf("failed to delete %s: %v", dir, err)
		} else {
			n++
		}
	} else {
		vlogf("no SecurityUpdates dir found")
	}
	for _, dir := range donkiStagingDirs() {
		if dirExists(dir) {
			logf("[triage] Donki staging dir PRESENT: %s", dir)
			if err := deletePath(dir, dry); err != nil {
				warnf("failed to delete %s: %v", dir, err)
			} else {
				n++
			}
		}
	}
	for _, dir := range []string{os.Getenv("TEMP"), os.Getenv("TMP"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp")} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "sqlite-jdbc-3.23.1.jar")
		if exists(p) {
			logf("[remove] Donki sqlite driver drop: %s", p)
			if dry {
				n++
				continue
			}
			if err := os.Remove(p); err != nil {
				warnf("cannot delete %s: %v", p, err)
			} else {
				n++
			}
		}
	}

	discordBase := filepath.Join(os.Getenv("LOCALAPPDATA"), "Discord")
	if dirExists(discordBase) {
		_ = filepath.WalkDir(discordBase, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.EqualFold(filepath.Base(p), "index.js") || !strings.Contains(strings.ToLower(p), "discord_desktop_core") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			lower := bytes.ToLower(data)
			hit := bytes.Contains(lower, []byte("/api/static/index.js")) ||
				bytes.Contains(lower, []byte("x-tracking-id")) ||
				bytes.Contains(data, []byte(donkiContract)) ||
				bytes.Contains(lower, []byte("donki")) ||
				bytes.Contains(lower, []byte("discord_desktop_core")) && bytes.Contains(lower, []byte("/api/receive"))
			if !hit {
				return nil
			}
			logf("[injection] Donki Discord injection hit: %s", p)
			fx := finding{Path: p, Kind: "startup", Family: "donki", Verdict: "CONFIRMED", Score: 10, Reasons: []string{"discord_desktop_core/index.js carries Donki markers; reinstall Discord after removal"}}
			if _, qerr := quarantineFile(p, quarantine, fx, dry); qerr != nil {
				warnf("cannot quarantine %s: %v", p, qerr)
			} else {
				n++
			}
			return nil
		})
	}
	if n == 0 {
		vlogf("no Donki staging artifacts found")
	}
	return n
}

func cleanWannaCry(dry bool) int {
	if out, code := runCmd("sc.exe", "query", "mssecsvc2.0"); code != 0 {
		vlogf("mssecsvc2.0 service absent (good)")
		return 0
	} else {
		vlogf("mssecsvc2.0 query:\n%s", firstLines(out, 4))
	}
	logf("[service] WannaCry mssecsvc2.0 PRESENT")
	if dry {
		logf("[dry-run] would stop+delete mssecsvc2.0")
		return 1
	}
	runCmd("sc.exe", "stop", "mssecsvc2.0")
	if _, code := runCmd("sc.exe", "delete", "mssecsvc2.0"); code == 0 {
		logf("[service] deleted mssecsvc2.0")
		return 1
	}
	warnf("cannot delete mssecsvc2.0 (run as admin / SYSTEM)")
	return 0
}

func regDeleteTree(key string, dry bool) bool {
	if dry {
		logf("[dry-run] would delete registry tree %s", key)
		return true
	}
	_, code := runCmd("reg", "delete", key, "/f")
	if code == 0 {
		logf("[registry] deleted %s", key)
		return true
	}
	vlogf("registry tree absent or delete failed (%d): %s", code, key)
	return false
}

func regFindValues(key, needle string) [][3]string {
	out, code := runCmd("reg", "query", key)
	if code != 0 {
		return nil
	}
	var hits [][3]string
	needle = strings.ToLower(needle)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "HKEY_") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		data := strings.Join(fields[2:], " ")
		if strings.Contains(strings.ToLower(line), needle) {
			hits = append(hits, [3]string{key, name, data})
		}
	}
	return hits
}

func cleanRegistry(dry bool) int {
	cleaned := 0

	for _, k := range []string{
		`HKCU\Software\Microsoft\Windows\NtProfileIndex`,
		`HKLM\Software\Microsoft\Windows\NtProfileIndex`,
	} {
		out, code := runCmd("reg", "query", k)
		if code == 0 {
			logf("[registry] found %s:\n%s", k, firstLines(out, 8))
			if regDeleteTree(k, dry) {
				cleaned++
			}
		}
	}

	runKeys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, key := range runKeys {
		for _, needle := range []string{"ntprofileindex", "apphost\\main.py", "_spawn.log", "jvmtp", "majanito", "sys-cache", "securitymanager", "donki_staging", "majanito.security", "abe_decrypt", "dont-elevate", "securityupdates"} {
			for _, hit := range regFindValues(key, needle) {
				logf("[registry] autorun hit: %s -> %s = %s", hit[0], hit[1], hit[2])
				if dry {
					cleaned++
					continue
				}
				if _, code := runCmd("reg", "delete", hit[0], "/v", hit[1], "/f"); code == 0 {
					logf("[registry] deleted value %s in %s", hit[1], hit[0])
					cleaned++
				} else {
					warnf("cannot delete registry value %s in %s (run as admin)", hit[1], hit[0])
				}
			}
		}
	}
	if cleaned == 0 {
		logf("[registry] no stealer keys/values found")
	}
	return cleaned
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func cleanScheduledTasks(dry bool) int {
	out, code := runCmd("schtasks", "/query", "/fo", "csv", "/v")
	if code != 0 {
		vlogf("schtasks query failed (exit %d), skipping", code)
		return 0
	}
	r := csv.NewReader(strings.NewReader(out))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return 0
	}
	header := rows[0]
	idxName, idxRun := -1, -1
	for i, h := range header {
		lh := strings.ToLower(strings.TrimSpace(h))
		if strings.Contains(lh, "taskname") {
			idxName = i
		}
		if strings.Contains(lh, "task to run") || strings.Contains(lh, "tasktorun") {
			idxRun = i
		}
	}
	cleaned := 0
	for _, row := range rows[1:] {
		get := func(i int) string {
			if i >= 0 && i < len(row) {
				return row[i]
			}
			return ""
		}
		name, run := get(idxName), get(idxRun)
		blob := strings.ToLower(name + " " + run + " " + strings.Join(row, " "))

		if strings.Contains(blob, "ntprofileindex") ||
			strings.Contains(blob, "apphost\\main.py") ||
			strings.Contains(blob, "apphost/main.py") ||
			strings.Contains(blob, "app.pyd") ||
			strings.Contains(blob, "securitymanager") ||
			strings.Contains(blob, "donki_staging") ||
			strings.Contains(blob, "dev.majanito.security") ||
			strings.Contains(blob, "jvmtp-") ||
			strings.Contains(blob, "--jw") ||
			strings.Contains(blob, "thread_silent") ||
			strings.Contains(blob, ".sys-cache") {
			logf("[tasks] hit: %s -> %s", name, run)
			if dry {
				cleaned++
				continue
			}
			if _, c := runCmd("schtasks", "/delete", "/tn", name, "/f"); c == 0 {
				logf("[tasks] deleted %s", name)
				cleaned++
			} else {
				warnf("cannot delete task %s (run as admin)", name)
			}
		}
	}
	if cleaned == 0 {
		vlogf("no stealer scheduled tasks found")
	}
	return cleaned
}

func cleanStartup(dry bool, quarantine string) int {
	startups := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
	}
	n := 0
	for _, dir := range startups {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			blob := append(append([]byte{}, data...), utf16LE(string(data))...)
			lowerBlob := bytes.ToLower(data)
			hitReason := ""
			switch {
			case bytes.Contains(lowerBlob, []byte("ntprofileindex")) || bytes.Contains(data, utf16LE("NtProfileIndex")):
				hitReason = "Startup entry references NtProfileIndex"
			case bytes.Contains(lowerBlob, []byte("securitymanager")) || bytes.Contains(lowerBlob, []byte("donki_staging")) || bytes.Contains(lowerBlob, []byte("dev.majanito.security")):
				hitReason = "Startup entry references Donki staging (SecurityManager/donki_staging)"
			}
			if hitReason != "" {
				_ = blob
				logf("[startup] hit: %s (%s)", p, hitReason)
				if *fDelete {
					if dry {
						logf("[dry-run] would delete %s", p)
					} else if err := os.Remove(p); err == nil {
						logf("[startup] deleted %s", p)
					}
				} else {
					fam := "silentnet"
					if strings.Contains(hitReason, "Donki") {
						fam = "donki"
					}
					fx := finding{Path: p, Kind: "startup", Family: fam, Verdict: "CONFIRMED", Score: 10, Reasons: []string{hitReason}}
					if _, err := quarantineFile(p, quarantine, fx, dry); err != nil {
						warnf("cannot quarantine %s: %v", p, err)
					}
				}
				n++
			}
		}
	}
	if n == 0 {
		vlogf("no Startup folder hits")
	}
	return n
}

func hardenHost(dry bool) {
	if *fNoHarden {
		logf("[harden] skipped (--no-harden)")
		return
	}
	if !isAdmin() {
		warnf("not running as Administrator: hosts/firewall hardening will be skipped (removal still proceeds).")
		warnf("To harden: re-run this tool as admin, or manually block %s and %s",
			strings.Join(c2Domains, ", "), strings.Join(c2IPs, ", "))
		return
	}

	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	extraDomains := []string{
		"api.x-grabber.com",
		"wxsgrabber-default-rtdb.europe-west1.firebasedatabase.app",
		"receiver.cy",
		"fucktermedfir.st",
		"falseflag1.ru",
		"whnewreceive.ru",
		"weedhack.cy",
	}
	if data, err := os.ReadFile(hostsPath); err == nil {
		missing := []string{}
		lower := strings.ToLower(string(data))
		for _, d := range append(append([]string{}, c2Domains...), extraDomains...) {
			if !strings.Contains(lower, strings.ToLower(d)) {
				missing = append(missing, d)
			}
		}
		if len(missing) > 0 {
			logf("[harden] adding hosts blocks for: %s", strings.Join(missing, ", "))
			if !dry {
				backup := hostsPath + ".mrt.bak"
				if !exists(backup) {
					os.WriteFile(backup, data, 0644)
				}
				fh, err := os.OpenFile(hostsPath, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					warnf("cannot append to hosts file: %v", err)
				} else {
					fmt.Fprintf(fh, "\n# MRT %s — C2 sinkhole (SilentNet/WeedHack/WXSGrabber; Donki C2 is on-chain, nothing static to block)\n", time.Now().Format("2006-01-02"))
					for _, d := range missing {
						fmt.Fprintf(fh, "0.0.0.0 %s\n0.0.0.0 www.%s\n", d, d)
					}
					fh.Close()
				}
			}
		} else {
			logf("[harden] hosts file already blocks C2 domains")
		}
	} else {
		warnf("cannot read hosts file: %v", err)
	}

	for _, ip := range c2IPs {
		name := "MRT-Block-" + strings.ReplaceAll(ip, ".", "-")
		out, _ := runCmd("netsh", "advfirewall", "firewall", "show", "rule", "name="+name)
		if strings.Contains(out, name) {
			vlogf("firewall rule exists: %s", name)
			continue
		}
		logf("[harden] adding firewall block: %s (%s)", name, ip)
		if !dry {
			if _, code := runCmd("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+name, "dir=out", "action=block", "remoteip="+ip,
				"description=MRT C2 block"); code != 0 {
				warnf("failed to add firewall rule for %s", ip)
			}
		}
	}
	if _, code := runCmd("ipconfig", "/flushdns"); code == 0 {
		logf("[harden] DNS cache flushed")
	}
}

func confirmOrExit(nFindings int, stagingPresent, pipePresent bool) {
	if *fYes || *fDryRun || *fScanOnly {
		return
	}
	outln()
	outf("Found %d dropper file(s). Staging present: %v. Pipe %s present: %v.",
		nFindings, stagingPresent, pipeName, pipePresent)
	outPrint("Proceed with KILL + QUARANTINE + DELETE staging + registry/task cleanup? [y/N]: ")
	var ans string
	fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "y" && ans != "yes" {
		outln("Aborted by user. Re-run with --scan-only to just report, or --yes to proceed.")
		os.Exit(2)
	}
}

func printPostRemovalChecklist(families map[string]bool) {
	outln()
	outln("==================== POST-REMOVAL — READ THIS ====================")
	outln("Wiping the box does NOT revoke what was already exfiltrated.")
	if families["silentnet"] {
		outln("SilentNet stage-2 steals: browser passwords/cookies/cards, Discord tokens,")
		outln("crypto wallets/seeds, Minecraft session tokens, SSH/FTP/VPN creds,")
		outln("Telegram sessions, screenshots and keyword-targeted files.")
	}
	if families["weedhack"] {
		outln("WeedHack steals: Minecraft session token + browser/Discord/wallet data,")
		outln("and its premium stage-2 is a full RAT (keylogger, webcam, shell).")
		outln("Assume full compromise — re-image if RAT activity is suspected.")
	}
	if families["wxsgrabber"] {
		outln("WXSGrabber steals: browser credentials, Discord tokens, crypto wallets,")
		outln("Minecraft/Microsoft sessions, and runs a live RAT (shell, screenshots).")
	}
	if families["donki"] {
		outln("Donki steals: Chromium/Firefox passwords+cookies (incl. Chrome 127+ ABE")
		outln("bypass via suspended-browser injection), Discord tokens + client injection")
		outln("(discord_desktop_core/index.js), 37-browser wallet extensions, desktop")
		outln("wallets (Exodus/Atomic/Electrum/...), Minecraft/Steam/Roblox sessions,")
		outln("Modrinth DB, and drops stage-2 SecurityManager.jar (registry persistence).")
		outln("Reinstall Discord after removal; assume wallets/sessions are compromised.")
	}
	if families["destructive"] {
		outln("Wiper/ransomware ran here: WannaCry encrypts files (restore from BACKUP,")
		outln("do NOT pay; patch MS17-010); NotPetya destroys the MBR (re-image);")
		outln("Stuxnet spreads via USB/LNK (scan removable media on a clean box).")
	}
	if families["generic"] {
		outln("Generic heuristics fired: file(s) combined independent red flags")
		outln("(Defender tampering, encoded execution, credential theft, remote")
		outln("exfil, persistence, injection). Review the listed reasons - a lone")
		outln("flag never convicts, so these files earned it twice over.")
	}
	outln()
	outln("On a CLEAN device, immediately:")
	outln("  1. Change passwords for every account used on this PC (browsers first),")
	outln("     then Discord, Google/Microsoft, Steam, Git, VPN, banking/crypto.")
	outln("  2. Discord: Settings > Authorized Apps + Devices > log out all sessions,")
	outln("     rotate any bot/webhook tokens stored on this PC.")
	outln("  3. Browsers: revoke sessions (Google/Facebook/etc. device lists),")
	outln("     rotate payment cards if autofill was enabled.")
	outln("  4. Crypto: move funds to a fresh wallet created on a CLEAN device;")
	outln("     treat any seed/extension data on this PC as compromised.")
	outln("  5. Minecraft: change Mojang/Microsoft password, invalidate session")
	outln("     tokens, check .minecraft/servers.dat + launcher_accounts.json.")
	outln("  6. SSH/FTP keys, .env files, FileZilla/WinSCP/PuTTY creds: rotate all.")
	outln("  7. Reboot, then re-run this tool with --scan-only to verify clean.")
	outln("==================================================================")
}

func main() {
	flag.Parse()
	initLogFile()
	defer closeLogFile()
	outf("MRT v%s — multi-family malware removal (Windows, Go, YARA-guided)", toolVersion)
	outf("Families: SilentNet | WeedHack/Majanito | WXSGrabber | Donki | destructive hashes (WannaCry/NotPetya/Stuxnet) | generic heuristics")
	outf("SilentNet C2: %s | weedhack C2 rotates via ETH %s | donki C2 resolves via ETH %s",
		strings.Join(c2Domains, ", "), weedhackContract, donkiContract)

	loadYaraLiterals()

	if *fListLaunchers {
		outln("Known game launchers (mod/instance coverage):")
		for _, l := range knownGameLaunchers() {
			status := "not installed"
			for _, p := range l.Paths {
				if dirExists(expandPathEnv(p)) {
					status = "INSTALLED"
					break
				}
			}
			outf("  [%-13s] %s\n", status, l.Name)
			for _, p := range l.Paths {
				mark := " "
				if dirExists(expandPathEnv(p)) {
					mark = "+"
				}
				outf("   %s %s\n", mark, expandPathEnv(p))
			}
		}
		return
	}

	if *fDryRun {
		logf("--dry-run: no changes will be made")
	}

	if found := detectGameLaunchers(); len(found) > 0 {
		logf("[triage] detected launchers: %s", strings.Join(found, ", "))
	} else {
		logf("[triage] no known game launchers detected")
	}
	sd := stagingDir()
	stagingPresent := dirExists(sd)
	pipePresent := pipeExists()
	logf("[triage] staging dir: %s present=%v", sd, stagingPresent)
	logf("[triage] pipe %s present=%v", pipeName, pipePresent)
	donkiSec := donkiSecurityDir()
	donkiSecPresent := dirExists(donkiSec)
	logf("[triage] Donki stage-2 dir: %s present=%v", donkiSec, donkiSecPresent)
	donkiStagePresent := false
	for _, d := range donkiStagingDirs() {
		if dirExists(d) {
			logf("[triage] Donki staging dir PRESENT: %s", d)
			donkiStagePresent = true
		}
	}
	if !donkiStagePresent {
		vlogf("no donki_staging dirs found")
	}
	donkiPipePresent := donkiPipeExists()
	logf("[triage] pipe %s* present=%v", donkiPipePrefix, donkiPipePresent)
	if stagingPresent {
		if h, err := sha256File(filepath.Join(sd, "AppHost", "main.py")); err == nil {
			if h == mainPySHA256 {
				logf("[triage] AppHost/main.py hash matches known SilentNet loader — infection CONFIRMED")
			} else {
				logf("[triage] AppHost/main.py present (hash %s...)", h[:16])
			}
		}
	}
	procs := listProcesses()
	liveTargets := 0
	for _, p := range procs {
		if ok, reason := isStealerProcess(p); ok {
			logf("[triage] live process: PID %s %s — %s", p.PID, p.Exe, reason)
			liveTargets++
		}
	}
	if liveTargets == 0 {
		vlogf("no live stealer processes matched")
	}

	roots := defaultScanRoots(*fFull)
	logf("[scan] roots (%d):", len(roots))
	for _, r := range roots {
		logf("         %s", r)
	}
	files := collectCandidates(roots)
	logf("[scan] candidate files: %d (.jar/.zip/.exe/.dll/scripts)", len(files))
	findings := scanFiles(files)

	confirmed, suspicious := 0, 0
	families := map[string]bool{}
	for _, f := range findings {
		tag := "SUSPICIOUS"
		if f.Verdict == "CONFIRMED" {
			tag = "CONFIRMED"
			confirmed++
		} else {
			suspicious++
		}
		if f.Family != "" {
			families[f.Family] = true
		}
		yaraNote := ""
		if len(f.YaraHits) > 0 {
			yaraNote = " | yara: " + strings.Join(f.YaraHits, ",")
		}
		logf("[%s] %s\n         family=%s kind=%s score=%d sha256=%.16s... size=%d\n         %s%s",
			tag, f.Path, f.Family, f.Kind, f.Score, f.SHA256, f.Size,
			strings.Join(f.Reasons, "; "), yaraNote)
	}
	logf("[scan] done: %d CONFIRMED, %d SUSPICIOUS out of %d candidates", confirmed, suspicious, len(files))

	if *fScanOnly {
		if confirmed+suspicious+boolToInt(stagingPresent)+boolToInt(pipePresent)+boolToInt(donkiSecPresent)+boolToInt(donkiStagePresent)+boolToInt(donkiPipePresent)+liveTargets > 0 {
			outln("RESULT: indicators found (see above). Re-run without --scan-only --yes to remove.")
			os.Exit(1)
		}
		outln("RESULT: no malware indicators found.")
		return
	}

	confirmOrExit(len(findings), stagingPresent || donkiSecPresent || donkiStagePresent, pipePresent || donkiPipePresent)

	qdir := quarantineDir()
	if !*fDelete {
		logf("[quarantine] dir: %s", qdir)
	}

	killed := killProcesses(procs, *fDryRun)
	logf("[kill] terminated %d stealer process(es)", killed)

	time.Sleep(800 * time.Millisecond)

	handled := 0
	for _, f := range findings {
		if f.Verdict == "clean" {
			continue
		}
		if !*fAllowSampleDir && isSampleCollection(f.Path) {
			warnf("skipping %s: inside the C:\\MALWARE research collection (use --allow-sample-dir to override)", f.Path)
			continue
		}
		if *fDelete {
			if *fDryRun {
				logf("[dry-run] would delete %s", f.Path)
			} else if err := os.Remove(f.Path); err != nil {
				warnf("cannot delete %s: %v (quarantining instead)", f.Path, err)
				if _, qerr := quarantineFile(f.Path, qdir, f, false); qerr == nil {
					handled++
				}
			} else {
				logf("[delete] %s", f.Path)
				handled++
			}
		} else {
			if _, err := quarantineFile(f.Path, qdir, f, *fDryRun); err != nil {
				warnf("cannot quarantine %s: %v", f.Path, err)
			} else {
				handled++
			}
		}
	}
	logf("[droppers] handled %d file(s)", handled)

	stagingOK := removeStaging(*fDryRun)
	nLogs := cleanSpawnLogs(*fDryRun)
	nWeed := cleanWeedHack(*fDryRun)
	nWXS := cleanWXS(*fDryRun)
	nDonki := cleanDonki(*fDryRun, qdir)
	nWcry := cleanWannaCry(*fDryRun)
	if exists(`C:\Windows\perfc`) {
		logf("[triage] C:\\Windows\\perfc present: NotPetya vaccine file — do NOT delete it")
	}
	nReg := cleanRegistry(*fDryRun)
	nTasks := cleanScheduledTasks(*fDryRun)
	nStartup := cleanStartup(*fDryRun, qdir)

	hardenHost(*fDryRun)

	time.Sleep(500 * time.Millisecond)
	stillStaging := dirExists(stagingDir())
	stillPipe := pipeExists()
	stillSysCache := dirExists(filepath.Join(os.Getenv("APPDATA"), ".sys-cache"))
	stillDonkiSec := dirExists(donkiSecurityDir())
	stillDonkiStage := false
	for _, d := range donkiStagingDirs() {
		if dirExists(d) {
			stillDonkiStage = true
		}
	}
	stillDonkiPipe := donkiPipeExists()
	stillDonkiSqlite := false
	for _, dir := range []string{os.Getenv("TEMP"), os.Getenv("TMP")} {
		if dir != "" && exists(filepath.Join(dir, "sqlite-jdbc-3.23.1.jar")) {
			stillDonkiSqlite = true
		}
	}
	stillJvmtp := false
	for _, dir := range []string{os.Getenv("TEMP"), os.Getenv("TMP")} {
		if m, _ := filepath.Glob(filepath.Join(dir, "jvmtp-*.dll")); len(m) > 0 {
			stillJvmtp = true
		}
	}
	procs2 := listProcesses()
	stillLive := 0
	for _, p := range procs2 {
		if ok, _ := isStealerProcess(p); ok {
			stillLive++
		}
	}
	outln()
	outln("==================== VERIFY ====================")
	outf("staging removed: %v (was present: %v)\n", !stillStaging && stagingOK, stagingPresent)
	outf("pipe gone:       %v (was present: %v)\n", !stillPipe, pipePresent)
	outf("sys-cache gone:  %v | jvmtp DLLs gone: %v\n", !stillSysCache, !stillJvmtp)
	outf("donki sec gone:  %v (was present: %v) | donki_staging gone: %v | abe pipe gone: %v | sqlite drop gone: %v\n",
		!stillDonkiSec, donkiSecPresent, !stillDonkiStage, !stillDonkiPipe, !stillDonkiSqlite)
	outf("live procs left: %d (killed: %d)\n", stillLive, killed)
	outf("droppers handled: %d | spawn logs: %d | weedhack natives: %d | wxs: %d | donki: %d | wannacry svc: %d | registry: %d | tasks: %d | startup: %d\n",
		handled, nLogs, nWeed, nWXS, nDonki, nWcry, nReg, nTasks, nStartup)
	if !stillStaging && !stillPipe && !stillSysCache && !stillJvmtp && !stillDonkiSec && !stillDonkiStage && !stillDonkiPipe && !stillDonkiSqlite && stillLive == 0 {
		outln("RESULT: malware appears REMOVED from this host.")
	} else {
		outln("RESULT: INCOMPLETE — reboot into Safe Mode, re-run as admin with --yes,")
		outln("        then re-run --scan-only. Do not restore quarantined files.")
	}
	printPostRemovalChecklist(families)

	if stillStaging || stillPipe || stillSysCache || stillJvmtp || stillDonkiSec || stillDonkiStage || stillDonkiPipe || stillDonkiSqlite || stillLive > 0 {
		os.Exit(1)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
