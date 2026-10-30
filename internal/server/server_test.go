package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFlow: setup -> add scope+tokens -> tok login (device flow) -> list -> use -> approval window.
func TestFlow(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{URL: "http://localhost:19191", DataDir: dir, KeyFile: dir + "/k"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := func(path string, v url.Values) {
		t.Helper()
		r, err := web.PostForm(ts.URL+path, v)
		if err != nil || r.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST %s: %v %v", path, err, r.Status)
		}
	}
	js := func(c *http.Client, bearer, path string, in any, out any) int {
		t.Helper()
		raw, _ := json.Marshal(in)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(raw))
		if in == nil {
			req, _ = http.NewRequest("GET", ts.URL+path, nil)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		if out != nil {
			_ = json.NewDecoder(r.Body).Decode(out)
		}
		return r.StatusCode
	}

	const pw = "correct horse battery"
	form("/setup", url.Values{"password": {pw}, "password2": {pw}})
	form("/scopes", url.Values{"name": {"acme"}})
	form("/settings/default-scope", url.Values{"default_scope": {"acme"}})
	if r, _ := web.Get(ts.URL + "/tokens/new"); r != nil {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "<option selected>acme</option>") {
			t.Fatal("default scope not preselected on new token form")
		}
	}
	// a validation error must keep everything that was typed
	if r, err := web.PostForm(ts.URL+"/tokens", url.Values{"name": {"!!!"}, "scope": {"acme"}, "value": {"typed-secret-123"}, "description": {"typed desc"}, "expires_at": {"2030-01-31"}}); err != nil {
		t.Fatal(err)
	} else {
		b, _ := io.ReadAll(r.Body)
		for _, want := range []string{"typed-secret-123", "typed desc", "2030-01-31", `typed-secret-123`} {
			if !strings.Contains(string(b), want) {
				t.Fatalf("re-rendered form lost %q", want)
			}
		}
	}
	form("/tokens", url.Values{"name": {"zabbix-acme"}, "scope": {"acme"}, "value": {"abcdefghijklmnop"}, "description": {"zabbix api"}})
	form("/tokens", url.Values{"name": {"prod-db"}, "scope": {"acme"}, "value": {"short"}, "needs_approval": {"on"}})
	form("/tokens", url.Values{"name": {"ha"}, "scope": {"home"}, "value": {"home-secret-1234"}})

	// device login limited to acme
	var start map[string]any
	js(http.DefaultClient, "", "/api/device/start", map[string]string{"host": "testhost"}, &start)
	code := start["user_code"].(string)
	if st := js(web, "", "/device/"+code, map[string]any{"password": "wrong", "scopes": []string{"acme"}}, nil); st != 401 {
		t.Fatalf("wrong password accepted: %d", st)
	}
	if st := js(web, "", "/device/"+code, map[string]any{"password": pw, "scopes": []string{"acme"}, "hours": 24}, nil); st != 200 {
		t.Fatalf("device approve: %d", st)
	}
	var login map[string]any
	js(http.DefaultClient, "", "/api/device/poll", map[string]any{"device_code": start["device_code"]}, &login)
	bearer, _ := login["token"].(string)
	if !strings.HasPrefix(bearer, "tok_") {
		t.Fatalf("no token: %v", login)
	}
	if st := js(http.DefaultClient, "", "/api/device/poll", map[string]any{"device_code": start["device_code"]}, nil); st == 200 {
		t.Fatal("token handed out twice")
	}

	var list struct{ Tokens []map[string]any }
	js(http.DefaultClient, bearer, "/api/tokens", nil, &list)
	if len(list.Tokens) != 2 {
		t.Fatalf("want 2 acme tokens, got %v", list.Tokens)
	}

	use := func(name, reason string) (int, map[string]any) {
		var out map[string]any
		st := js(http.DefaultClient, bearer, "/api/use", map[string]string{"name": name, "reason": reason}, &out)
		return st, out
	}
	if st, _ := use("zabbix-acme", "short"); st != 400 {
		t.Fatalf("short reason accepted: %d", st)
	}
	if st, _ := use("ha", "checking home assistant state"); st != 404 {
		t.Fatalf("out-of-scope token served: %d", st)
	}
	if st, out := use("zabbix-acme", "list zabbix problems for acme"); st != 200 || out["value"] != "abcdefghijklmnop" || out["env_name"] != "ZABBIX_ACME" {
		t.Fatalf("use: %d %v", st, out)
	}
	st, out := use("prod-db", "run a read-only query on prod")
	if st != 202 {
		t.Fatalf("approval not required: %d %v", st, out)
	}
	id := out["request_id"].(string)
	if _, again := use("prod-db", "run a read-only query on prod"); again["request_id"] != id {
		t.Fatal("retry opened a second approval request")
	}
	if st := js(web, "", "/approve/"+id, map[string]any{"password": pw, "minutes": 15}, nil); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	if st, out := use("prod-db", "run a read-only query on prod"); st != 200 || out["value"] != "short" {
		t.Fatalf("use after approval: %d %v", st, out)
	}

	if n := s.db.usedTokens(time.Now().Add(-time.Hour)); n != 2 {
		t.Fatalf("usedTokens = %d, want 2", n)
	}
	if r, _ := web.Get(ts.URL + "/"); r != nil {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "Most used, last 30 days") || !strings.Contains(string(b), "run a read-only query on prod") {
			t.Fatal("dashboard missing stats or recent requests")
		}
	}
	evs, _ := s.db.events(EventFilter{Kind: "use"})
	if len(evs) != 2 || evs[0].Reason == "" || evs[0].Host != "testhost" {
		t.Fatalf("events: %+v", evs)
	}
	if evs, _ := s.db.events(EventFilter{Q: "read-only query"}); len(evs) == 0 {
		t.Fatal("context search found nothing")
	}
	if evs, _ := s.db.events(EventFilter{Q: "%"}); len(evs) != 0 {
		t.Fatalf("LIKE wildcard not escaped: %d events", len(evs))
	}
	if got := funcs["agentvars"].(func(string) [][2]string)("AI_AGENT=claude CLAUDE_CODE_SESSION_ID=6e67-a2 X=a b"); len(got) != 3 || got[1] != [2]string{"CLAUDE_CODE_SESSION_ID", "6e67-a2"} || got[2][1] != "a b" {
		t.Fatalf("agentvars: %q", got)
	}
	s.db.logEvent(Event{Kind: "use", Token: "old", TS: time.Now().AddDate(0, 0, -40)})
	form("/settings/retention", url.Values{"event_retention_days": {"30"}})
	if evs, _ := s.db.events(EventFilter{Token: "old"}); len(evs) != 0 {
		t.Fatal("retention did not purge old events")
	}
	for in, want := range map[string]string{
		"AI_AGENT=claude-code_2-1-314_agent CLAUDE_CODE_SESSION_ID=x T3CODE_THREAD_ID=y": "claude",
		"CODEX_THREAD_ID=abc":                     "openai",
		"AI_AGENT=codex CLAUDE_CODE_SESSION_ID=x": "openai", // AI_AGENT is the most specific signal
		"T3CODE_THREAD_ID=y":                      "",
		"":                                        "",
	} {
		if got := detectAgent(in).Key; got != want {
			t.Errorf("detectAgent(%q) = %q, want %q", in, got, want)
		}
	}
	for _, path := range []string{"/favicon.ico", "/static/brand/favicon.svg", "/static/brand/site.webmanifest"} {
		if r, err := http.Get(ts.URL + path); err != nil || r.StatusCode != 200 {
			t.Fatalf("GET %s: %v %v", path, err, r)
		}
	}
	// a reveal (value shown to an agent) needs a fresh approval each time, even without needs_approval
	reveal := func() (int, map[string]any) {
		var out map[string]any
		st := js(http.DefaultClient, bearer, "/api/use", map[string]any{"name": "zabbix-acme", "reason": "print it for the user who asked", "reveal": true}, &out)
		return st, out
	}
	st, out = reveal()
	if st != 202 || out["reveal"] != true {
		t.Fatalf("reveal without approval: %d %v", st, out)
	}
	if st := js(web, "", "/approve/"+out["request_id"].(string), map[string]any{"password": pw}, nil); st != 200 {
		t.Fatalf("approve reveal: %d", st)
	}
	if st, out := reveal(); st != 200 || out["value"] != "abcdefghijklmnop" {
		t.Fatalf("reveal after approval: %d %v", st, out)
	}
	if st, _ := reveal(); st != 202 {
		t.Fatalf("second reveal reused the approval: %d", st)
	}
	if st, _ := use("zabbix-acme", "plain use is unaffected by reveal"); st != 200 {
		t.Fatalf("plain use after reveal: %d", st)
	}
	// a one-year login is allowed by default; revoked logins can be cleaned up
	var start2 map[string]any
	js(http.DefaultClient, "", "/api/device/start", map[string]string{"host": "yearhost"}, &start2)
	if st := js(web, "", "/device/"+start2["user_code"].(string), map[string]any{"password": pw, "scopes": []string{"acme"}, "hours": 24 * 365}, nil); st != 200 {
		t.Fatalf("one-year login refused: %d", st)
	}
	form("/logins/1/revoke", url.Values{})
	form("/logins/cleanup", url.Values{})
	if ls, _ := s.db.logins(); len(ls) != 1 || ls[0].Host != "yearhost" {
		t.Fatalf("cleanup should leave only the active login, got %d", len(ls))
	}
	for peak, want := range map[int][2]int{0: {1, 1}, 1: {1, 1}, 4: {4, 1}, 10: {10, 5}, 14: {15, 5}, 55: {60, 20}, 101: {150, 50}} {
		if top, step := niceScale(peak); top != want[0] || step != want[1] {
			t.Errorf("niceScale(%d) = %d, %d, want %v", peak, top, step, want)
		}
	}
	for in, want := range map[string]string{"Zabbix ACME api!": "zabbix_acme_api", " prod--db ": "prod--db", "a  b\tc": "a_b_c", "!!!": "", "Žalias raktas": "alias_raktas"} {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
	if m := mask("abcdefghijklmnop"); m != "abc••••••••nop" {
		t.Fatalf("mask: %s", m)
	}
}
