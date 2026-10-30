package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		claude, codex, codexHome, override bool
		link, fail                         string
	}{
		{name: "no agents"},
		{name: "claude", claude: true},
		{name: "codex command", codex: true},
		{name: "codex home", codexHome: true},
		{name: "both", claude: true, codex: true},
		{name: "override", claude: true, codex: true, override: true},
		{name: "directory symlink", claude: true, link: "directory"},
		{name: "file symlink", claude: true, link: "file"},
		{name: "failed skill download", claude: true, fail: "skill"},
		{name: "failed binary download", claude: true, fail: "binary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			write := func(path, content string, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			mock := filepath.Join(home, "mock")
			// Isolate PATH so installed host agents cannot affect detection.
			if err := os.MkdirAll(mock, 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"uname", "tr", "mkdir", "mktemp", "chmod", "mv", "rm"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(mock, name)); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(mock, "curl"), `#!/bin/sh
case "$2" in
 */SKILL.md) kind=skill; content='new skill';;
 *) kind=binary; content='new binary';;
esac
printf '%s' "$content" > "$4"
if [ "$FAIL" = "$kind" ]; then exit 18; fi
`, 0755)
			if tc.codex {
				write(filepath.Join(mock, "codex"), "#!/bin/sh\n", 0755)
			}
			codexHome := filepath.Join(home, "custom codex home")
			if tc.codexHome {
				if err := os.MkdirAll(codexHome, 0755); err != nil {
					t.Fatal(err)
				}
			}
			claudeSkill := filepath.Join(home, ".claude", "skills", "tok", "SKILL.md")
			if tc.claude {
				write(claudeSkill, "old skill", 0644)
			}
			target := filepath.Join(home, "managed", "SKILL.md")
			if tc.link != "" {
				write(target, "managed skill", 0644)
				link, dest := claudeSkill, target
				if tc.link == "directory" {
					link, dest = filepath.Dir(link), filepath.Dir(dest)
				}
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dest, link); err != nil {
					t.Fatal(err)
				}
			}
			binary := filepath.Join(home, ".local", "bin", "tok")
			write(binary, "old binary", 0755)
			override := ""
			if tc.override {
				override = filepath.Join(home, "custom skills", "tok")
			}
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = strings.NewReader(strings.ReplaceAll(installSh, "@URL@", "https://example.invalid"))
			cmd.Env = []string{"HOME=" + home, "PATH=" + mock, "CODEX_HOME=" + codexHome, "TOK_SKILL_DIR=" + override, "FAIL=" + tc.fail}
			output, err := cmd.CombinedOutput()
			if (err != nil) != (tc.fail != "") {
				t.Fatalf("installer: %v\n%s", err, output)
			}
			check := func(path, want string) {
				t.Helper()
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("%s: got %q, %v; want %q", path, got, err, want)
				}
			}
			wantBin := "new binary"
			if tc.fail == "binary" {
				wantBin = "old binary"
			}
			check(binary, wantBin)
			if tc.claude {
				want := "new skill"
				if tc.override || tc.fail != "" {
					want = "old skill"
				}
				if tc.link != "" {
					want = "managed skill"
					check(target, want)
				}
				check(claudeSkill, want)
			}
			codexSkill := filepath.Join(home, ".agents", "skills", "tok", "SKILL.md")
			if (tc.codex || tc.codexHome) && !tc.override {
				check(codexSkill, "new skill")
			} else if _, err := os.Stat(codexSkill); !os.IsNotExist(err) {
				t.Fatalf("unexpected Codex skill: %v", err)
			}
			if tc.override {
				check(filepath.Join(override, "SKILL.md"), "new skill")
			}
			for _, pattern := range []string{filepath.Join(filepath.Dir(binary), ".tok.*"), filepath.Join(filepath.Dir(claudeSkill), ".SKILL.md.*")} {
				if matches, _ := filepath.Glob(pattern); len(matches) != 0 {
					t.Fatalf("temporary files remain: %v", matches)
				}
			}
		})
	}
}
