package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

// POST /api/device/start {host} — begins `tok login`.
func (s *Server) apiDeviceStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	_ = decode(r, &body)
	if !s.hasPassword() {
		jsonErr(w, 409, "server not set up yet: open "+s.cfg.URL+"/setup")
		return
	}
	d := &device{
		DeviceCode: randToken(32),
		UserCode:   userCode(),
		Host:       trimTo(body.Host, 100),
		Created:    time.Now(),
		Expires:    time.Now().Add(deviceTTL),
		Status:     "pending",
	}
	s.mu.Lock()
	s.devices[d.DeviceCode] = d
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"device_code": d.DeviceCode,
		"user_code":   d.UserCode,
		"verify_url":  s.cfg.URL + "/device?code=" + d.UserCode,
		"interval":    2,
		"expires_in":  int(deviceTTL.Seconds()),
	})
}

// POST /api/device/poll {device_code}
func (s *Server) apiDevicePoll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	_ = decode(r, &body)
	s.mu.Lock()
	d, ok := s.devices[body.DeviceCode]
	var status, tok string
	var l *Login
	if ok {
		status, tok, l = d.Status, d.token, d.login
		if status == "approved" {
			d.Status, d.token = "collected", "" // the token is handed out exactly once
		}
	}
	s.mu.Unlock()
	switch {
	case !ok || time.Now().After(d.Expires):
		jsonErr(w, 410, "login request expired, run `tok login` again")
	case status == "pending":
		jsonErr(w, 428, "pending")
	case status == "approved":
		writeJSON(w, 200, map[string]any{"token": tok, "host": l.Host, "scopes": l.Scopes, "expires_at": l.ExpiresAt})
	default:
		jsonErr(w, 403, "login "+status)
	}
}

func (s *Server) apiWhoami(w http.ResponseWriter, r *http.Request, l *Login) {
	writeJSON(w, 200, map[string]any{"login_id": l.ID, "host": l.Host, "scopes": l.Scopes, "created_at": l.CreatedAt, "expires_at": l.ExpiresAt, "server": s.cfg.URL})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request, l *Login) {
	_, _ = s.db.Exec(`UPDATE logins SET revoked_at=? WHERE id=?`, time.Now().Unix(), l.ID)
	s.db.logEvent(Event{Kind: "logout", LoginID: &l.ID, Host: l.Host})
	writeJSON(w, 200, map[string]string{"ok": "logged out"})
}

// GET /api/tokens — catalog for the agent: metadata only, limited to the login's scopes.
func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, l *Login) {
	toks, err := s.db.tokens(l.Scopes)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	scopes, _ := s.db.scopes()
	var visible []Scope
	for _, sc := range scopes {
		if l.HasScope(sc.Name) {
			visible = append(visible, sc)
		}
	}
	type item struct {
		*Token
		Expired bool `json:"expired,omitempty"`
	}
	out := []item{}
	for _, t := range toks {
		out = append(out, item{t, t.Expired()})
	}
	writeJSON(w, 200, map[string]any{"scopes": visible, "tokens": out})
}

type useRequest struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Cwd    string `json:"cwd"`
	Cmd    string `json:"cmd"`
	Agent  string `json:"agent"`
	Reveal bool   `json:"reveal"` // the value will be shown to an agent; always needs a fresh approval
}

// POST /api/use — the only way to get a value. Every call is logged with its reason.
func (s *Server) apiUse(w http.ResponseWriter, r *http.Request, l *Login) {
	var req useRequest
	if err := decode(r, &req); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	ev := Event{Token: req.Name, LoginID: &l.ID, Host: l.Host, Reason: trimTo(req.Reason, 1000),
		Cwd: trimTo(req.Cwd, 500), Cmd: trimTo(req.Cmd, 2000), Agent: trimTo(req.Agent, 300)}
	deny := func(code int, msg string) {
		ev.Kind, ev.Detail = "denied", msg
		s.db.logEvent(ev)
		jsonErr(w, code, msg)
	}
	if len([]rune(req.Reason)) < minReasonLength {
		deny(400, fmt.Sprintf("a reason of at least %d characters is required: say what you are doing and why this token", minReasonLength))
		return
	}
	t, err := s.db.tokenByName(req.Name)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if t == nil || !l.HasScope(t.Scope) {
		deny(404, "no such token in this login's scopes ("+strings.Join(l.Scopes, ", ")+")")
		return
	}
	ev.Scope = t.Scope
	if t.Expired() {
		deny(410, "token expired on "+t.ExpiresAt.Format("2006-01-02")+"; ask the owner for a new one")
		return
	}
	if t.NeedsApproval || req.Reveal {
		now := time.Now()
		granted := false
		s.mu.Lock()
		if req.Reveal { // one approved reveal request allows one collection
			for _, p := range s.requests {
				if p.Reveal && p.LoginID == l.ID && p.Token == t.Name && p.Status == "approved" && !p.Collected && now.Before(p.Until) {
					p.Collected, granted = true, true
					ev.Detail = "reveal approved, " + p.ID
					break
				}
			}
		} else if until, ok := s.grants[grantKey{l.ID, t.ID}]; ok && now.Before(until) {
			granted = true
			ev.Detail = "approved until " + until.Format("15:04:05")
		}
		s.mu.Unlock()
		if !granted {
			ar := &approvalRequest{ID: randToken(12), LoginID: l.ID, Host: l.Host, Token: t.Name, Scope: t.Scope,
				Reason: ev.Reason, Cwd: ev.Cwd, Cmd: ev.Cmd, Agent: ev.Agent,
				Created: now, Expires: now.Add(requestTTL), Status: "pending", Reveal: req.Reveal}
			s.mu.Lock()
			reused := false
			for _, p := range s.requests { // a retry while waiting reuses the open request
				if p.LoginID == l.ID && p.Token == t.Name && p.Reveal == req.Reveal && p.Status == "pending" && now.Before(p.Expires) {
					ar, reused = p, true
					break
				}
			}
			if !reused {
				s.requests[ar.ID] = ar
			}
			s.mu.Unlock()
			if !reused {
				ev.Kind, ev.Detail = "approval_requested", ar.ID
				if ar.Reveal {
					ev.Detail += " (reveal)"
				}
				s.db.logEvent(ev)
			}
			writeJSON(w, 202, map[string]any{
				"status":      "approval_required",
				"request_id":  ar.ID,
				"approve_url": s.cfg.URL + "/approve/" + ar.ID,
				"expires_at":  ar.Expires,
				"reveal":      ar.Reveal,
				"reused":      reused,
			})
			return
		}
	}
	value, err := s.seal.open(t.Name, t.valueEnc)
	if err != nil {
		jsonErr(w, 500, "cannot decrypt token (wrong master key?)")
		return
	}
	_, _ = s.db.Exec(`UPDATE tokens SET last_used_at=? WHERE id=?`, time.Now().Unix(), t.ID)
	ev.Kind = "use"
	s.db.logEvent(ev)
	writeJSON(w, 200, map[string]any{"name": t.Name, "env_name": t.EnvName, "value": value})
}

// GET /api/requests/{id} — CLI polls this while waiting for approval.
func (s *Server) apiRequest(w http.ResponseWriter, r *http.Request, l *Login) {
	s.mu.Lock()
	ar, ok := s.requests[r.PathValue("id")]
	var status string
	if ok {
		status = ar.Status
		if status == "pending" && time.Now().After(ar.Expires) {
			status = "expired"
		}
	}
	s.mu.Unlock()
	if !ok || ar.LoginID != l.ID {
		jsonErr(w, 404, "unknown request")
		return
	}
	writeJSON(w, 200, map[string]string{"status": status})
}

func trimTo(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
