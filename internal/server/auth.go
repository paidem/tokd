package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
)

// owner is the single WebAuthn user.
type owner struct {
	id    []byte
	creds []webauthn.Credential
}

func (o *owner) WebAuthnID() []byte                         { return o.id }
func (o *owner) WebAuthnName() string                       { return "owner" }
func (o *owner) WebAuthnDisplayName() string                { return "tokd owner" }
func (o *owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

type passkeyRow struct {
	ID        int64
	Name      string
	CreatedAt time.Time
	LastUsed  *time.Time
	cred      webauthn.Credential
}

func (s *Server) passkeys() ([]passkeyRow, error) {
	rows, err := s.db.Query(`SELECT id, name, credential, created_at, last_used_at FROM passkeys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []passkeyRow
	for rows.Next() {
		var p passkeyRow
		var raw string
		var created int64
		var last *int64
		if err := rows.Scan(&p.ID, &p.Name, &raw, &created, &last); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &p.cred); err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(created, 0)
		if last != nil {
			t := time.Unix(*last, 0)
			p.LastUsed = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Server) owner() (*owner, error) {
	id, err := s.db.setting("webauthn_user_id")
	if err != nil {
		return nil, err
	}
	if id == nil {
		id = []byte(randToken(32))
		if err := s.db.setSetting("webauthn_user_id", id); err != nil {
			return nil, err
		}
	}
	pks, err := s.passkeys()
	if err != nil {
		return nil, err
	}
	o := &owner{id: id}
	for _, p := range pks {
		o.creds = append(o.creds, p.cred)
	}
	return o, nil
}

func (s *Server) hasPassword() bool {
	h, _ := s.db.setting("password_hash")
	return h != nil
}

// --- brute-force brake: after 5 failures in 15 min, every attempt waits out an exponential lockout ---

func (s *Server) lockedFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	recent := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	s.failures = recent
	if len(recent) < 5 {
		return 0
	}
	wait := time.Second << min(len(recent)-5, 10)
	if left := time.Until(recent[len(recent)-1].Add(wait)); left > 0 {
		return left
	}
	return 0
}

func (s *Server) noteFailure() {
	s.mu.Lock()
	s.failures = append(s.failures, time.Now())
	s.mu.Unlock()
}

// authProof is sent by every confirmation form: either a password or a passkey assertion.
type authProof struct {
	Password   string          `json:"password"`
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// verify checks a password or a passkey assertion. Returns a user-facing error.
func (s *Server) verify(p authProof) error {
	if d := s.lockedFor(); d > 0 {
		return fmt.Errorf("too many failed attempts, retry in %s", d.Round(time.Second))
	}
	if len(p.Credential) > 0 {
		if err := s.verifyPasskey(p); err != nil {
			s.noteFailure()
			return fmt.Errorf("passkey not accepted: %v", err)
		}
		return nil
	}
	h, err := s.db.setting("password_hash")
	if err != nil || h == nil || p.Password == "" || bcrypt.CompareHashAndPassword(h, []byte(p.Password)) != nil {
		s.noteFailure()
		return errUnauthorized
	}
	return nil
}

func (s *Server) verifyPasskey(p authProof) error {
	s.mu.Lock()
	c, ok := s.ceremonies[p.Ceremony]
	delete(s.ceremonies, p.Ceremony)
	s.mu.Unlock()
	if !ok || time.Now().After(c.expires) {
		return fmt.Errorf("ceremony expired, try again")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(p.Credential))
	if err != nil {
		return err
	}
	o, err := s.owner()
	if err != nil {
		return err
	}
	cred, err := s.wa.ValidateLogin(o, *c.data, parsed)
	if err != nil {
		return err
	}
	// persist the updated sign counter
	raw, _ := json.Marshal(cred)
	pks, _ := s.passkeys()
	for _, pk := range pks {
		if bytes.Equal(pk.cred.ID, cred.ID) {
			_, err = s.db.Exec(`UPDATE passkeys SET credential=?, last_used_at=? WHERE id=?`, string(raw), time.Now().Unix(), pk.ID)
		}
	}
	return err
}

func (s *Server) newCeremony(data *webauthn.SessionData) string {
	id := randToken(16)
	s.mu.Lock()
	s.ceremonies[id] = ceremony{data: data, expires: time.Now().Add(ceremonyTTL)}
	s.mu.Unlock()
	return id
}

// GET /auth/passkey/begin -> assertion options for any confirmation form.
func (s *Server) passkeyAssertBegin(w http.ResponseWriter, r *http.Request) {
	o, err := s.owner()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if len(o.creds) == 0 {
		jsonErr(w, 404, "no passkeys registered")
		return
	}
	opts, data, err := s.wa.BeginLogin(o, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony": s.newCeremony(data), "options": opts})
}

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	o, err := s.owner()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range o.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := s.wa.BeginRegistration(o,
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony": s.newCeremony(data), "options": opts})
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ceremony   string          `json:"ceremony"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	c, ok := s.ceremonies[body.Ceremony]
	delete(s.ceremonies, body.Ceremony)
	s.mu.Unlock()
	if !ok {
		jsonErr(w, 400, "ceremony expired, try again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body.Credential))
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	o, err := s.owner()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	cred, err := s.wa.CreateCredential(o, *c.data, parsed)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(cred)
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "passkey " + time.Now().Format("2006-01-02")
	}
	if _, err := s.db.Exec(`INSERT INTO passkeys(name, credential, created_at) VALUES(?,?,?)`, name, string(raw), time.Now().Unix()); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s.db.logEvent(Event{Kind: "passkey_added", Detail: name})
	writeJSON(w, 200, map[string]string{"ok": "registered"})
}

func (s *Server) doPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	_, _ = s.db.Exec(`DELETE FROM passkeys WHERE id=?`, r.PathValue("id"))
	s.db.logEvent(Event{Kind: "passkey_deleted", Detail: r.PathValue("id")})
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// --- browser session ---

const sessionCookie = "tokd_session"

func (s *Server) startSession(w http.ResponseWriter) {
	id := randToken(32)
	s.mu.Lock()
	s.sessions[id] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
}

func (s *Server) hasSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	return ok && time.Now().Before(exp)
}

func (s *Server) withSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hasPassword() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if !s.hasSession(r) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

func (s *Server) doLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- CLI login token ---

func (s *Server) withLogin(h func(http.ResponseWriter, *http.Request, *Login)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			jsonErr(w, 401, "not logged in: run `tok login <server>`")
			return
		}
		l, err := s.db.loginByHash(hashToken(tok))
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if l == nil || !l.Active() {
			jsonErr(w, 401, "login expired or revoked: run `tok login`")
			return
		}
		_, _ = s.db.Exec(`UPDATE logins SET last_seen_at=? WHERE id=?`, time.Now().Unix(), l.ID)
		h(w, r, l)
	}
}
