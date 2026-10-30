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
# Installs the tok client and the Claude Code skill from @URL@
# Env: TOK_BIN_DIR (default ~/.local/bin), TOK_SKILL_DIR (default ~/.claude/skills/tok)
set -eu
URL="@URL@"

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
curl -fsSL "$URL/dl/tok-$os-$arch" -o "$BIN_DIR/tok.tmp"
chmod 755 "$BIN_DIR/tok.tmp"
mv "$BIN_DIR/tok.tmp" "$BIN_DIR/tok"
echo "installed $BIN_DIR/tok"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not in PATH; add it to your shell profile" ;;
esac

SKILL_DIR="${TOK_SKILL_DIR:-$HOME/.claude/skills/tok}"
if [ -L "$SKILL_DIR" ]; then
  echo "skill: $SKILL_DIR is a symlink, left untouched"
elif [ -d "$HOME/.claude" ] || [ -n "${TOK_SKILL_DIR:-}" ]; then
  mkdir -p "$SKILL_DIR"
  curl -fsSL "$URL/dl/SKILL.md" -o "$SKILL_DIR/SKILL.md"
  echo "installed skill $SKILL_DIR/SKILL.md"
else
  echo "skill: no ~/.claude here; for other agents fetch $URL/dl/SKILL.md"
fi

echo
echo "Next: tok login $URL"
`
