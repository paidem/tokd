package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// releaseRepo publishes the tok binaries and the tokd image (GitHub releases).
const releaseRepo = "paidem/tokd"

// latestRelease returns the newest release tag, cached next to the config for maxAge so that
// status lines don't hit the GitHub API (60 requests/hour unauthenticated) on every run.
func latestRelease(maxAge time.Duration) (string, error) {
	cache := filepath.Join(filepath.Dir(configPath()), "latest.json")
	var c struct {
		Tag     string    `json:"tag"`
		Checked time.Time `json:"checked"`
	}
	if raw, err := os.ReadFile(cache); err == nil && json.Unmarshal(raw, &c) == nil && c.Tag != "" && time.Since(c.Checked) < maxAge {
		return c.Tag, nil
	}
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get("https://api.github.com/repos/" + releaseRepo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub releases: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil || rel.Tag == "" {
		return "", errors.New("GitHub releases: no tag in the response")
	}
	c.Tag, c.Checked = rel.Tag, time.Now()
	if raw, err := json.Marshal(c); err == nil {
		_ = os.MkdirAll(filepath.Dir(cache), 0o700)
		_ = os.WriteFile(cache, raw, 0o600)
	}
	return c.Tag, nil
}

// semver parses vMAJOR.MINOR.PATCH (pre-release suffixes ignored); ok is false for dev builds.
func semver(v string) (n [3]int, ok bool) {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return n, false
	}
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil {
			return n, false
		}
		n[i] = x
	}
	return n, true
}

// newer reports whether release a is newer than b; false if either is not a release version.
func newer(a, b string) bool {
	x, ok1 := semver(a)
	y, ok2 := semver(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

// updateNotes lists what is out of date given the server's version ("" if unknown). Errors
// (offline, rate limit) are silent: these lines are a courtesy, not a check.
func updateNotes(serverVersion string) []string {
	latest, err := latestRelease(24 * time.Hour)
	if err != nil {
		return nil
	}
	var notes []string
	if newer(latest, version) {
		notes = append(notes, fmt.Sprintf("tok %s is available (you have %s): run tok update", latest, version))
	}
	if newer(latest, serverVersion) {
		notes = append(notes, fmt.Sprintf("tokd %s is available (the server runs %s): https://github.com/%s/releases/tag/%s", latest, serverVersion, releaseRepo, latest))
	}
	return notes
}

func download(url string) ([]byte, error) {
	hc := &http.Client{Timeout: 2 * time.Minute}
	resp, err := hc.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// cmdUpdate replaces this binary with the latest release, verified against its SHA256SUMS,
// and refreshes the Claude Code skill if it is a plain file (a symlink is left alone).
func cmdUpdate(args []string) error {
	force := len(args) == 1 && args[0] == "--force"
	if len(args) > 0 && !force {
		return errors.New("usage: tok update [--force]")
	}
	latest, err := latestRelease(0)
	if err != nil {
		return fmt.Errorf("cannot check for a new release: %w", err)
	}
	if _, ok := semver(version); !ok && !force {
		return fmt.Errorf("this is a development build (%s); tok update --force replaces it with %s", version, latest)
	}
	if !newer(latest, version) && !force {
		fmt.Printf("tok %s is up to date\n", version)
		return nil
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	asset := fmt.Sprintf("tok-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s/", releaseRepo, latest)
	sums, err := download(base + "SHA256SUMS")
	if err != nil {
		return err
	}
	want := ""
	for sc := bufio.NewScanner(bytes.NewReader(sums)); sc.Scan(); {
		if f := strings.Fields(sc.Text()); len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("release %s has no %s", latest, asset)
	}
	bin, err := download(base + asset)
	if err != nil {
		return err
	}
	if got := sha256.Sum256(bin); hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("checksum mismatch for %s; not installed", asset)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return fmt.Errorf("cannot write next to %s: %w", exe, err)
	}
	if runtime.GOOS == "windows" { // a running .exe can be renamed but not overwritten
		_ = os.Remove(exe + ".old")
		if err := os.Rename(exe, exe+".old"); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	fmt.Printf("tok updated: %s -> %s (%s)\n", version, latest, exe)

	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".claude", "skills", "tok")
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
		if fi, err := os.Lstat(filepath.Join(dir, "SKILL.md")); err == nil && fi.Mode().IsRegular() {
			if md, err := download(base + "SKILL.md"); err == nil && os.WriteFile(filepath.Join(dir, "SKILL.md"), md, 0o644) == nil {
				fmt.Println("skill updated:", filepath.Join(dir, "SKILL.md"))
			}
		}
	}
	return nil
}
