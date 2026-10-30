package server

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticRoot embed.FS

var staticFS fs.FS = staticRoot

var funcs = template.FuncMap{
	"when": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			return v.Format("2006-01-02 15:04")
		case *time.Time:
			if v == nil {
				return ""
			}
			return v.Format("2006-01-02 15:04")
		}
		return ""
	},
	"ago": func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		d := time.Since(*t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return fmt.Sprintf("%d min ago", int(d.Minutes()))
		case d < 48*time.Hour:
			return fmt.Sprintf("%d h ago", int(d.Hours()))
		}
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	},
	"date": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			return v.Format("2006-01-02")
		case *time.Time:
			if v != nil {
				return v.Format("2006-01-02")
			}
		}
		return ""
	},
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
	"list":  func(v ...string) []string { return v },
	"div":   func(a, b int) int { return a / b },
	"join":  strings.Join,
	"until": func(t time.Time) string { return time.Until(t).Round(time.Minute).String() },
}

var pages = map[string]*template.Template{}

func init() {
	names, _ := fs.Glob(templateFS, "templates/*.html")
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		pages[base] = template.Must(template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", n))
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Page"] = page
	data["LoggedIn"] = s.hasSession(r)
	data["URL"] = s.cfg.URL
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *Server) hasPasskeys() bool {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM passkeys`).Scan(&n)
	return n > 0
}

// --- setup & login ---

func (s *Server) pageSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasPassword() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", nil)
}

func (s *Server) doSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasPassword() {
		http.Error(w, "already set up", 409)
		return
	}
	pw := r.FormValue("password")
	if len(pw) < 12 || pw != r.FormValue("password2") {
		s.render(w, r, "setup", map[string]any{"Error": "Passwords must match and be at least 12 characters."})
		return
	}
	if err := s.setPassword(pw); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, sc := range []string{"home", "work"} {
		_, _ = s.db.Exec(`INSERT OR IGNORE INTO scopes(name, created_at) VALUES(?,?)`, sc, time.Now().Unix())
	}
	s.db.logEvent(Event{Kind: "setup"})
	s.startSession(w)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) setPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	return s.db.setSetting("password_hash", h)
}

func (s *Server) pageLogin(w http.ResponseWriter, r *http.Request) {
	if !s.hasPassword() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", map[string]any{"Passkeys": s.hasPasskeys(), "Next": r.URL.Query().Get("next")})
}

// POST /login {authProof}
func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) {
	var p authProof
	if err := decode(r, &p); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := s.verify(p); err != nil {
		s.db.logEvent(Event{Kind: "web_login_failed", Detail: err.Error()})
		jsonErr(w, 401, err.Error())
		return
	}
	s.startSession(w)
	writeJSON(w, 200, map[string]string{"ok": "logged in"})
}

// --- device login approval (tok login) ---

func (s *Server) findDevice(userCode string) *device {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.UserCode == strings.ToUpper(strings.TrimSpace(userCode)) && time.Now().Before(d.Expires) {
			return d
		}
	}
	return nil
}

func (s *Server) pageDevice(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	d := s.findDevice(code)
	scopes, _ := s.db.scopes()
	var hours []int
	for _, h := range []int{1, 8, 24, 72, 168, 336, 720} {
		if h <= s.loginMaxHours() {
			hours = append(hours, h)
		}
	}
	s.render(w, r, "device", map[string]any{"Code": code, "Device": d, "Scopes": scopes, "Hours": hours,
		"DefaultHours": s.loginDefaultHours(), "Passkeys": s.hasPasskeys()})
}

// POST /device/{code} {authProof, scopes, hours, deny}
func (s *Server) doDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		authProof
		Scopes []string `json:"scopes"`
		Hours  int      `json:"hours"`
		Deny   bool     `json:"deny"`
	}
	if err := decode(r, &body); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	d := s.findDevice(r.PathValue("code"))
	if d == nil || d.Status != "pending" {
		jsonErr(w, 410, "login request not found or no longer pending")
		return
	}
	if body.Deny {
		s.mu.Lock()
		d.Status = "denied"
		s.mu.Unlock()
		s.db.logEvent(Event{Kind: "login_denied", Host: d.Host})
		writeJSON(w, 200, map[string]string{"ok": "denied"})
		return
	}
	if err := s.verify(body.authProof); err != nil {
		jsonErr(w, 401, err.Error())
		return
	}
	known, _ := s.db.scopes()
	var scopes []string
	for _, want := range body.Scopes {
		for _, k := range known {
			if k.Name == want {
				scopes = append(scopes, want)
			}
		}
	}
	if len(scopes) == 0 {
		jsonErr(w, 400, "pick at least one scope")
		return
	}
	if body.Hours <= 0 || body.Hours > s.loginMaxHours() {
		body.Hours = s.loginDefaultHours()
	}
	tok := "tok_" + randToken(32)
	now := time.Now()
	l := &Login{Host: d.Host, Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(time.Duration(body.Hours) * time.Hour)}
	res, err := s.db.Exec(`INSERT INTO logins(token_hash, host, scopes, created_at, expires_at) VALUES(?,?,?,?,?)`,
		hashToken(tok), l.Host, strings.Join(scopes, ","), now.Unix(), l.ExpiresAt.Unix())
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	l.ID, _ = res.LastInsertId()
	s.mu.Lock()
	d.Status, d.token, d.login = "approved", tok, l
	s.mu.Unlock()
	s.db.logEvent(Event{Kind: "login", LoginID: &l.ID, Host: l.Host, Detail: fmt.Sprintf("scopes %s for %dh", strings.Join(scopes, ","), body.Hours)})
	writeJSON(w, 200, map[string]string{"ok": "approved"})
}

// --- token use approval ---

func (s *Server) pageApprove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ar := s.requests[r.PathValue("id")]
	var cp approvalRequest
	if ar != nil {
		cp = *ar
	}
	s.mu.Unlock()
	data := map[string]any{"Windows": approvalWindows, "Passkeys": s.hasPasskeys()}
	if ar != nil {
		data["Req"] = &cp
		data["Expired"] = cp.Status == "pending" && time.Now().After(cp.Expires)
		if t, _ := s.db.tokenByName(cp.Token); t != nil {
			data["Token"] = t
		}
	}
	s.render(w, r, "approve", data)
}

// POST /approve/{id} {authProof, minutes, deny}
func (s *Server) doApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		authProof
		Minutes int  `json:"minutes"`
		Deny    bool `json:"deny"`
	}
	if err := decode(r, &body); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	ar := s.requests[r.PathValue("id")]
	ok := ar != nil && ar.Status == "pending" && time.Now().Before(ar.Expires)
	s.mu.Unlock()
	if !ok {
		jsonErr(w, 410, "request not found, expired or already decided")
		return
	}
	ev := Event{Token: ar.Token, Scope: ar.Scope, LoginID: &ar.LoginID, Host: ar.Host, Reason: ar.Reason, Cwd: ar.Cwd, Cmd: ar.Cmd, Agent: ar.Agent, Detail: ar.ID}
	if body.Deny {
		s.mu.Lock()
		ar.Status = "denied"
		s.mu.Unlock()
		ev.Kind = "approval_denied"
		s.db.logEvent(ev)
		writeJSON(w, 200, map[string]string{"ok": "denied"})
		return
	}
	if err := s.verify(body.authProof); err != nil {
		jsonErr(w, 401, err.Error())
		return
	}
	valid := false
	for _, m := range approvalWindows {
		valid = valid || m == body.Minutes
	}
	if !valid {
		body.Minutes = approvalWindows[0]
	}
	t, err := s.db.tokenByName(ar.Token)
	if err != nil || t == nil {
		jsonErr(w, 404, "token no longer exists")
		return
	}
	until := time.Now().Add(time.Duration(body.Minutes) * time.Minute)
	s.mu.Lock()
	ar.Status, ar.Until = "approved", until
	s.grants[grantKey{ar.LoginID, t.ID}] = until
	s.mu.Unlock()
	ev.Kind, ev.Detail = "approved", fmt.Sprintf("%s for %d min", ar.ID, body.Minutes)
	s.db.logEvent(ev)
	writeJSON(w, 200, map[string]string{"ok": "approved"})
}

// --- tokens ---

func (s *Server) pageTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.db.tokens(nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope != "" {
		var f []*Token
		for _, t := range toks {
			if t.Scope == scope {
				f = append(f, t)
			}
		}
		toks = f
	}
	scopes, _ := s.db.scopes()
	s.render(w, r, "tokens", map[string]any{"Tokens": toks, "Scopes": scopes, "Scope": scope, "Now": time.Now()})
}

func (s *Server) pageTokenEdit(w http.ResponseWriter, r *http.Request) {
	scopes, _ := s.db.scopes()
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		v, _ := s.db.setting("default_scope")
		scope = string(v)
	}
	data := map[string]any{"Scopes": scopes, "Token": &Token{Scope: scope}}
	if id := r.PathValue("id"); id != "" {
		n, _ := strconv.ParseInt(id, 10, 64)
		t, err := s.db.tokenByID(n)
		if err != nil || t == nil {
			http.NotFound(w, r)
			return
		}
		data["Token"], data["Edit"] = t, true
		data["Events"], _ = s.db.events(EventFilter{Token: t.Name, Limit: 50})
	}
	s.render(w, r, "token_edit", data)
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var nameJunk = regexp.MustCompile(`[^a-z0-9._-]+`)

// normalizeName turns "Zabbix ACME api!" into "zabbix_acme_api". Mirrored in static/app.js.
func normalizeName(s string) string {
	s = nameJunk.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "_")
	s = strings.Trim(s, "._-")
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "._-")
	}
	return s
}

var validEnv = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func (s *Server) doTokenSave(w http.ResponseWriter, r *http.Request) {
	var id int64
	var old *Token
	if p := r.PathValue("id"); p != "" {
		id, _ = strconv.ParseInt(p, 10, 64)
		old, _ = s.db.tokenByID(id)
		if old == nil {
			http.NotFound(w, r)
			return
		}
	}
	t := &Token{
		Name:          normalizeName(r.FormValue("name")),
		Scope:         r.FormValue("scope"),
		Description:   strings.TrimSpace(r.FormValue("description")),
		Usage:         strings.TrimSpace(r.FormValue("usage")),
		EnvName:       strings.TrimSpace(r.FormValue("env_name")),
		NeedsApproval: r.FormValue("needs_approval") == "on",
	}
	value := r.FormValue("value")
	value = strings.TrimRight(value, "\r\n")
	var expires *int64
	if e := r.FormValue("expires_at"); e != "" {
		tm, err := time.ParseInLocation("2006-01-02", e, time.Local)
		if err == nil {
			u := tm.Add(24*time.Hour - time.Second).Unix()
			expires = &u
		}
	}
	scopes, _ := s.db.scopes()
	fail := func(msg string) {
		if old != nil {
			t.ID = old.ID
		}
		if expires != nil {
			e := time.Unix(*expires, 0)
			t.ExpiresAt = &e
		}
		if old != nil && value == "" {
			t.Masked = old.Masked
		}
		// re-render everything that was typed, including the secret, so nothing has to be retyped
		s.render(w, r, "token_edit", map[string]any{"Scopes": scopes, "Token": t, "Edit": old != nil, "Error": msg, "Value": value})
	}
	switch {
	case !validName.MatchString(t.Name):
		fail("Name is required (letters, digits, dot, dash, underscore).")
		return
	case t.EnvName != "" && !validEnv.MatchString(t.EnvName):
		fail("Env var name must look like ZABBIX_TOKEN.")
		return
	case old == nil && value == "":
		fail("Secret value is required.")
		return
	}
	if t.EnvName == defaultEnvName(t.Name) {
		t.EnvName = ""
	}
	now := time.Now().Unix()
	if old == nil {
		_, err := s.db.Exec(`INSERT INTO tokens(name, scope, description, usage, env_name, value_enc, value_len, masked, needs_approval, expires_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			t.Name, t.Scope, t.Description, t.Usage, t.EnvName, s.seal.seal(t.Name, value), len(value), mask(value), t.NeedsApproval, expires, now, now)
		if err != nil {
			fail(friendlyDBError(err))
			return
		}
		s.db.logEvent(Event{Kind: "token_added", Token: t.Name, Scope: t.Scope})
	} else {
		enc := old.valueEnc
		if value != "" {
			enc = s.seal.seal(t.Name, value)
		} else if t.Name != old.Name { // ciphertext is bound to the name: re-seal on rename
			plain, err := s.seal.open(old.Name, old.valueEnc)
			if err != nil {
				fail("cannot decrypt old value to rename")
				return
			}
			enc = s.seal.seal(t.Name, plain)
		}
		q := `UPDATE tokens SET name=?, scope=?, description=?, usage=?, env_name=?, value_enc=?, needs_approval=?, expires_at=?, updated_at=?`
		args := []any{t.Name, t.Scope, t.Description, t.Usage, t.EnvName, enc, t.NeedsApproval, expires, now}
		if value != "" {
			q += `, value_len=?, masked=?`
			args = append(args, len(value), mask(value))
		}
		if _, err := s.db.Exec(q+` WHERE id=?`, append(args, id)...); err != nil {
			fail(friendlyDBError(err))
			return
		}
		detail := ""
		if value != "" {
			detail = "value replaced"
		}
		if t.Name != old.Name {
			detail = strings.TrimSpace(detail + " renamed from " + old.Name)
		}
		s.db.logEvent(Event{Kind: "token_updated", Token: t.Name, Scope: t.Scope, Detail: detail})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func friendlyDBError(err error) string {
	switch msg := err.Error(); {
	case strings.Contains(msg, "UNIQUE"):
		return "A token with this name already exists."
	case strings.Contains(msg, "FOREIGN KEY"):
		return "Pick an existing scope."
	default:
		return msg
	}
}

func (s *Server) doTokenDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if t, _ := s.db.tokenByID(id); t != nil {
		_, _ = s.db.Exec(`DELETE FROM tokens WHERE id=?`, id)
		s.db.logEvent(Event{Kind: "token_deleted", Token: t.Name, Scope: t.Scope})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) doTokenReveal(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, _ := s.db.tokenByID(id)
	if t == nil {
		jsonErr(w, 404, "not found")
		return
	}
	v, err := s.seal.open(t.Name, t.valueEnc)
	if err != nil {
		jsonErr(w, 500, "cannot decrypt")
		return
	}
	s.db.logEvent(Event{Kind: "revealed_in_web", Token: t.Name, Scope: t.Scope})
	writeJSON(w, 200, map[string]string{"value": v})
}

// --- scopes ---

func (s *Server) pageScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := s.db.scopes()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, r, "scopes", map[string]any{"Scopes": scopes, "Error": r.URL.Query().Get("error")})
}

func (s *Server) doScopeSave(w http.ResponseWriter, r *http.Request) {
	name := normalizeName(r.FormValue("name"))
	if !validName.MatchString(name) {
		http.Redirect(w, r, "/scopes?error=Scope+name:+lowercase+letters,+digits,+dash", http.StatusSeeOther)
		return
	}
	_, err := s.db.Exec(`INSERT INTO scopes(name, description, created_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description`,
		name, strings.TrimSpace(r.FormValue("description")), time.Now().Unix())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.db.logEvent(Event{Kind: "scope_saved", Scope: name})
	http.Redirect(w, r, "/scopes", http.StatusSeeOther)
}

func (s *Server) doScopeDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.db.Exec(`DELETE FROM scopes WHERE name=?`, name); err != nil {
		http.Redirect(w, r, "/scopes?error=Scope+still+has+tokens", http.StatusSeeOther)
		return
	}
	s.db.logEvent(Event{Kind: "scope_deleted", Scope: name})
	http.Redirect(w, r, "/scopes", http.StatusSeeOther)
}

// --- events, logins, settings ---

func (s *Server) pageEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{Token: q.Get("token"), Scope: q.Get("scope"), Kind: q.Get("kind"), Host: q.Get("host")}
	f.LoginID, _ = strconv.ParseInt(q.Get("login"), 10, 64)
	evs, err := s.db.events(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, r, "events", map[string]any{"Events": evs, "F": f})
}

func (s *Server) pageLogins(w http.ResponseWriter, r *http.Request) {
	ls, err := s.db.logins()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, r, "logins", map[string]any{"Logins": ls})
}

func (s *Server) doLoginRevoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_, _ = s.db.Exec(`UPDATE logins SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().Unix(), id)
	s.db.logEvent(Event{Kind: "login_revoked", LoginID: &id})
	http.Redirect(w, r, "/logins", http.StatusSeeOther)
}

func (s *Server) pageSettings(w http.ResponseWriter, r *http.Request) {
	pks, _ := s.passkeys()
	scopes, _ := s.db.scopes()
	def, _ := s.db.setting("default_scope")
	s.render(w, r, "settings", map[string]any{"Passkeys": pks, "DefaultHours": s.loginDefaultHours(), "MaxHours": s.loginMaxHours(),
		"Scopes": scopes, "DefaultScope": string(def), "Msg": r.URL.Query().Get("msg")})
}

func (s *Server) doDefaultScope(w http.ResponseWriter, r *http.Request) {
	scope := r.FormValue("default_scope") // empty = no default
	_ = s.db.setSetting("default_scope", []byte(scope))
	s.db.logEvent(Event{Kind: "settings_changed", Detail: "default scope for new tokens: " + scope})
	http.Redirect(w, r, "/settings?msg=Saved", http.StatusSeeOther)
}

func (s *Server) doSettings(w http.ResponseWriter, r *http.Request) {
	def, _ := strconv.Atoi(r.FormValue("login_default_hours"))
	max, _ := strconv.Atoi(r.FormValue("login_max_hours"))
	if def < 1 || max < def || max > 24*365 {
		http.Redirect(w, r, "/settings?msg=Default+must+be+between+1+hour+and+the+maximum", http.StatusSeeOther)
		return
	}
	_ = s.db.setSetting("login_default_hours", []byte(strconv.Itoa(def)))
	_ = s.db.setSetting("login_max_hours", []byte(strconv.Itoa(max)))
	s.db.logEvent(Event{Kind: "settings_changed", Detail: fmt.Sprintf("login default %dh, max %dh", def, max)})
	http.Redirect(w, r, "/settings?msg=Saved", http.StatusSeeOther)
}

func (s *Server) doPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.verify(authProof{Password: r.FormValue("current")}); err != nil {
		http.Redirect(w, r, "/settings?msg=Current+password+is+wrong", http.StatusSeeOther)
		return
	}
	pw := r.FormValue("password")
	if len(pw) < 12 || pw != r.FormValue("password2") {
		http.Redirect(w, r, "/settings?msg=New+passwords+must+match+and+be+at+least+12+characters", http.StatusSeeOther)
		return
	}
	if err := s.setPassword(pw); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.db.logEvent(Event{Kind: "password_changed"})
	http.Redirect(w, r, "/settings?msg=Password+changed", http.StatusSeeOther)
}
