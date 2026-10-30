package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGetNeedsRevealUnderAgent(t *testing.T) {
	for _, k := range []string{"AI_AGENT", "CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"} {
		t.Setenv(k, "")
	}
	t.Setenv("TOK_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv("CLAUDECODE", "1")
	if err := cmdGet([]string{"--reason", "why", "x"}); err == nil || !strings.Contains(err.Error(), "--reveal") {
		t.Fatalf("agent get without --reveal: %v", err)
	}
	// with --reveal it gets past the guard and fails on the missing login instead
	if err := cmdGet([]string{"--reveal", "--reason", "why", "x"}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("agent get with --reveal: %v", err)
	}
	t.Setenv("CLAUDECODE", "")
	if err := cmdGet([]string{"--reason", "why", "x"}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("human get: %v", err)
	}
}
