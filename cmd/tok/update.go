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

type release struct {
	Tag     string    `json:"tag"` // the release (and tokd image) version
	Tok     string    `json:"tok"` // version the release's tok binaries report; reused binaries keep an older one
	Checked time.Time `json:"checked"`
}

// latestRelease returns the newest release, cached next to the config for maxAge so that
// status lines don't hit the GitHub API (60 requests/hour unauthenticated) on every run.
func latestRelease(maxAge time.Duration) (release, error) {
	cache := filepath.Join(filepath.Dir(configPath()), "latest.json")
	var c release
	if raw, err := os.ReadFile(cache); err == nil && json.Unmarshal(raw, &c) == nil && c.Tag != "" && c.Tok != "" && time.Since(c.Checked) < maxAge {
		return c, nil
	}
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get("https://api.github.com/repos/" + releaseRepo + "/releases/latest")
	if err != nil {
		return c, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return c, fmt.Errorf("GitHub releases: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil || rel.Tag == "" {
		return c, errors.New("GitHub releases: no tag in the response")
	}
	c = release{Tag: rel.Tag, Tok: rel.Tag, Checked: time.Now()}
	if r, err := hc.Get(assetURL(rel.Tag, "TOK_VERSION")); err == nil { // missing before v0.3.0: binaries match the tag
		if b, _ := io.ReadAll(io.LimitReader(r.Body, 64)); r.StatusCode == 200 && strings.TrimSpace(string(b)) != "" {
			c.Tok = strings.TrimSpace(string(b))
		}
		r.Body.Close()
	}
	if raw, err := json.Marshal(c); err == nil {
		_ = os.MkdirAll(filepath.Dir(cache), 0o700)
		_ = os.WriteFile(cache, raw, 0o600)
	}
	return c, nil
}

func assetURL(tag, name string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", releaseRepo, tag, name)
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
	if newer(latest.Tok, version) {
		notes = append(notes, fmt.Sprintf("tok %s is available (you have %s): run tok update", latest.Tok, version))
	}
	if newer(latest.Tag, serverVersion) {
		notes = append(notes, fmt.Sprintf("tokd %s is available (the server runs %s): https://github.com/%s/releases/tag/%s", latest.Tag, serverVersion, releaseRepo, latest.Tag))
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
	check := len(args) == 1 && args[0] == "--check" // report only, install nothing
	if len(args) > 0 && !force && !check {
		return errors.New("usage: tok update [--check | --force]")
	}
	latest, err := latestRelease(0)
	if err != nil {
		return fmt.Errorf("cannot check for a new release: %w", err)
	}
	if check {
		if newer(latest.Tok, version) {
			fmt.Printf("tok %s is available (you have %s): run tok update\n", latest.Tok, version)
		} else {
			fmt.Printf("tok %s is up to date (latest release %s)\n", version, latest.Tag)
		}
		return nil
	}
	if _, ok := semver(version); !ok && !force {
		return fmt.Errorf("this is a development build (%s); tok update --force replaces it with %s", version, latest.Tok)
	}
	if !newer(latest.Tok, version) && !force {
		fmt.Printf("tok %s is up to date\n", version)
		return nil
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	asset := fmt.Sprintf("tok-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
	sums, err := download(assetURL(latest.Tag, "SHA256SUMS"))
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
		return fmt.Errorf("release %s has no %s", latest.Tag, asset)
	}
	bin, err := download(assetURL(latest.Tag, asset))
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
	fmt.Printf("tok updated: %s -> %s (%s)\nRelease notes: https://github.com/%s/releases/tag/%s\n", version, latest.Tok, exe, releaseRepo, latest.Tag)

	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".claude", "skills", "tok")
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
		if fi, err := os.Lstat(filepath.Join(dir, "SKILL.md")); err == nil && fi.Mode().IsRegular() {
			if md, err := download(assetURL(latest.Tag, "SKILL.md")); err == nil && os.WriteFile(filepath.Join(dir, "SKILL.md"), md, 0o644) == nil {
				fmt.Println("skill updated:", filepath.Join(dir, "SKILL.md"))
			}
		}
	}
	return nil
}
