package server

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
)

// pageInstall is public: it only offers the client binaries and the agent skill.
func (s *Server) pageInstall(w http.ResponseWriter, r *http.Request) {
	var files []string
	entries, _ := fs.ReadDir(os.DirFS(s.cfg.Downloads), ".")
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "TOK_VERSION" { // TOK_VERSION is for tok update, not people
			files = append(files, e.Name())
		}
	}
	s.render(w, r, "install", map[string]any{"Files": files})
}

func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(installSh, "@URL@", s.cfg.URL)))
}

const installSh = `#!/bin/sh
# Installs tok and skills for detected Claude Code and Codex installations.
# Env: TOK_BIN_DIR (default ~/.local/bin), TOK_SKILL_DIR (overrides skill detection)
set -eu
URL="@URL@"
tmp=
trap 'rm -f "$tmp"' 0
trap 'exit 1' HUP INT TERM

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "tok: unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac
case "$os" in
  darwin|linux) ;;
  *) echo "tok: unsupported OS $os; download manually from $URL/install" >&2; exit 1 ;;
esac

BIN_DIR="${TOK_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
tmp=$(mktemp "$BIN_DIR/.tok.XXXXXX")
curl -fsSL "$URL/dl/tok-$os-$arch" -o "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "$BIN_DIR/tok"
echo "installed $BIN_DIR/tok"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not in PATH; add it to your shell profile" ;;
esac

install_skill() {
  skill_dir=$1
  if [ -L "$skill_dir" ] || [ -L "$skill_dir/SKILL.md" ]; then
    echo "skill: $skill_dir or its SKILL.md is a symlink, left untouched"
    return
  fi
  if [ -e "$skill_dir/SKILL.md" ] && [ ! -f "$skill_dir/SKILL.md" ]; then
    echo "skill: $skill_dir/SKILL.md is not a regular file" >&2
    exit 1
  fi
  mkdir -p "$skill_dir"
  tmp=$(mktemp "$skill_dir/.SKILL.md.XXXXXX")
  curl -fsSL "$URL/dl/SKILL.md" -o "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$skill_dir/SKILL.md"
  echo "installed skill $skill_dir/SKILL.md"
}

if [ -n "${TOK_SKILL_DIR:-}" ]; then
  install_skill "$TOK_SKILL_DIR"
else
  found=
  if [ -d "$HOME/.claude" ]; then
    install_skill "$HOME/.claude/skills/tok"
    found=1
  fi
  if command -v codex >/dev/null 2>&1 || [ -d "${CODEX_HOME:-$HOME/.codex}" ]; then
    install_skill "$HOME/.agents/skills/tok"
    found=1
  fi
  if [ -z "$found" ]; then
    echo "skill: no Claude Code or Codex found; for other agents fetch $URL/dl/SKILL.md"
  fi
fi

echo
echo "Next: tok login $URL"
`
