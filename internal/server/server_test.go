package server

import (
	"bytes"
	"io"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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

	evs, _ := s.db.events(EventFilter{Kind: "use"})
	if len(evs) != 2 || evs[0].Reason == "" || evs[0].Host != "testhost" {
		t.Fatalf("events: %+v", evs)
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
