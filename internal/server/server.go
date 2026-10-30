package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Config struct {
	Addr    string // listen address, e.g. ":19191"
	URL     string // public origin as typed in the browser, e.g. "http://localhost:19191"
	DataDir string
	KeyFile string
}

func ConfigFromEnv() Config {
	c := Config{
		Addr:    env("TOKD_ADDR", ":19191"),
		URL:     strings.TrimRight(env("TOKD_URL", "http://localhost:19191"), "/"),
		DataDir: env("TOKD_DATA", "./data"),
	}
	c.KeyFile = env("TOKD_KEY_FILE", filepath.Join(c.DataDir, "master.key"))
	return c
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const (
	sessionTTL      = 12 * time.Hour
	ceremonyTTL     = 5 * time.Minute
	deviceTTL       = 10 * time.Minute
	requestTTL      = 10 * time.Minute
	minReasonLength = 10
)

var approvalWindows = []int{5, 15, 60} // minutes offered on the approval page

type Server struct {
	cfg    Config
	db     *DB
	seal   *sealer
	wa     *webauthn.WebAuthn
	secure bool // cookies get Secure when served over https

	mu         sync.Mutex
	sessions   map[string]time.Time
	ceremonies map[string]ceremony
	devices    map[string]*device // by device code
	requests   map[string]*approvalRequest
	grants     map[grantKey]time.Time
	failures   []time.Time
}

type ceremony struct {
	data    *webauthn.SessionData
	expires time.Time
}

type device struct {
	DeviceCode string
	UserCode   string
	Host       string
	Created    time.Time
	Expires    time.Time
	Status     string // pending | approved | denied | collected
	token      string
	login      *Login
}

type approvalRequest struct {
	ID      string
	LoginID int64
	Host    string
	Token   string
	Scope   string
	Reason  string
	Cwd     string
	Cmd     string
	Agent   string
	Created time.Time
	Expires time.Time
	Status  string // pending | approved | denied
	Until   time.Time
}

type grantKey struct {
	login int64
	token int64
}

func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	db, err := openDB(filepath.Join(cfg.DataDir, "tokd.db"))
	if err != nil {
		return nil, err
	}
	seal, err := loadKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("TOKD_URL %q is not an absolute URL", cfg.URL)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "tokd",
		RPOrigins:     []string{cfg.URL},
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, db: db, seal: seal, wa: wa, secure: u.Scheme == "https",
		sessions:   map[string]time.Time{},
		ceremonies: map[string]ceremony{},
		devices:    map[string]*device{},
		requests:   map[string]*approvalRequest{},
		grants:     map[grantKey]time.Time{},
	}, nil
}

func (s *Server) ListenAndServe() error {
	go s.janitor()
	log.Printf("tokd listening on %s, public URL %s", s.cfg.Addr, s.cfg.URL)
	srv := &http.Server{Addr: s.cfg.Addr, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	// agent / CLI API (bearer login token, except device start/poll)
	m.HandleFunc("POST /api/device/start", s.apiDeviceStart)
	m.HandleFunc("POST /api/device/poll", s.apiDevicePoll)
	m.HandleFunc("GET /api/whoami", s.withLogin(s.apiWhoami))
	m.HandleFunc("GET /api/tokens", s.withLogin(s.apiTokens))
	m.HandleFunc("POST /api/use", s.withLogin(s.apiUse))
	m.HandleFunc("GET /api/requests/{id}", s.withLogin(s.apiRequest))
	m.HandleFunc("POST /api/logout", s.withLogin(s.apiLogout))

	// confirmation ceremonies (public pages, each action re-authenticates)
	m.HandleFunc("GET /auth/passkey/begin", s.passkeyAssertBegin)
	m.HandleFunc("GET /login", s.pageLogin)
	m.HandleFunc("POST /login", s.doLogin)
	m.HandleFunc("GET /setup", s.pageSetup)
	m.HandleFunc("POST /setup", s.doSetup)
	m.HandleFunc("GET /device", s.pageDevice)
	m.HandleFunc("POST /device/{code}", s.doDevice)
	m.HandleFunc("GET /approve/{id}", s.pageApprove)
	m.HandleFunc("POST /approve/{id}", s.doApprove)

	// admin web app (session cookie)
	m.HandleFunc("POST /logout", s.withSession(s.doLogout))
	m.HandleFunc("GET /{$}", s.withSession(s.pageTokens))
	m.HandleFunc("GET /tokens/new", s.withSession(s.pageTokenEdit))
	m.HandleFunc("GET /tokens/{id}", s.withSession(s.pageTokenEdit))
	m.HandleFunc("POST /tokens", s.withSession(s.doTokenSave))
	m.HandleFunc("POST /tokens/{id}", s.withSession(s.doTokenSave))
	m.HandleFunc("POST /tokens/{id}/delete", s.withSession(s.doTokenDelete))
	m.HandleFunc("POST /tokens/{id}/reveal", s.withSession(s.doTokenReveal))
	m.HandleFunc("GET /scopes", s.withSession(s.pageScopes))
	m.HandleFunc("POST /scopes", s.withSession(s.doScopeSave))
	m.HandleFunc("POST /scopes/{name}/delete", s.withSession(s.doScopeDelete))
	m.HandleFunc("GET /events", s.withSession(s.pageEvents))
	m.HandleFunc("GET /logins", s.withSession(s.pageLogins))
	m.HandleFunc("POST /logins/{id}/revoke", s.withSession(s.doLoginRevoke))
	m.HandleFunc("GET /settings", s.withSession(s.pageSettings))
	m.HandleFunc("POST /settings", s.withSession(s.doSettings))
	m.HandleFunc("POST /settings/password", s.withSession(s.doPassword))
	m.HandleFunc("GET /passkeys/begin", s.withSession(s.passkeyRegisterBegin))
	m.HandleFunc("POST /passkeys/finish", s.withSession(s.passkeyRegisterFinish))
	m.HandleFunc("POST /passkeys/{id}/delete", s.withSession(s.doPasskeyDelete))
	m.Handle("GET /static/", http.FileServerFS(staticFS))
	return s.sameOrigin(m)
}

// sameOrigin rejects cross-site browser POSTs (CSRF). CLI requests carry no Origin header.
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" && o != s.cfg.URL {
				http.Error(w, "cross-origin request refused (check TOKD_URL)", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.sessions {
			if now.After(v) {
				delete(s.sessions, k)
			}
		}
		for k, v := range s.ceremonies {
			if now.After(v.expires) {
				delete(s.ceremonies, k)
			}
		}
		for k, v := range s.devices {
			if now.After(v.Expires) {
				delete(s.devices, k)
			}
		}
		for k, v := range s.requests {
			if now.After(v.Expires) && now.After(v.Until) {
				delete(s.requests, k)
			}
		}
		for k, v := range s.grants {
			if now.After(v) {
				delete(s.grants, k)
			}
		}
		s.mu.Unlock()
	}
}

// --- settings stored in the DB ---

func (s *Server) intSetting(k string, def int) int {
	v, _ := s.db.setting(k)
	if n, err := strconv.Atoi(string(v)); err == nil {
		return n
	}
	return def
}

func (s *Server) loginDefaultHours() int { return s.intSetting("login_default_hours", 24) }
func (s *Server) loginMaxHours() int     { return s.intSetting("login_max_hours", 168) }

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

var errUnauthorized = errors.New("unauthorized")
