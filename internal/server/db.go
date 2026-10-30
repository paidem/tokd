package server

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scopes (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL REFERENCES scopes(name) ON UPDATE CASCADE,
  description TEXT NOT NULL DEFAULT '',
  usage TEXT NOT NULL DEFAULT '',
  env_name TEXT NOT NULL DEFAULT '',
  value_enc BLOB NOT NULL,
  value_len INTEGER NOT NULL,
  masked TEXT NOT NULL,
  needs_approval INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS logins (
  id INTEGER PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS passkeys (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  credential TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  token TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  login_id INTEGER,
  host TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  cwd TEXT NOT NULL DEFAULT '',
  cmd TEXT NOT NULL DEFAULT '',
  agent TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_token ON events(token);
`

type DB struct{ *sql.DB }

func openDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // chisle: single writer is plenty for one user
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) setting(k string) ([]byte, error) {
	var v []byte
	err := db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func (db *DB) setSetting(k string, v []byte) error {
	_, err := db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

type Scope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tokens      int    `json:"tokens"`
}

func (db *DB) scopes() ([]Scope, error) {
	rows, err := db.Query(`SELECT s.name, s.description, (SELECT count(*) FROM tokens t WHERE t.scope=s.name) FROM scopes s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scope
	for rows.Next() {
		var s Scope
		if err := rows.Scan(&s.Name, &s.Description, &s.Tokens); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

type Token struct {
	ID            int64      `json:"-"`
	Name          string     `json:"name"`
	Scope         string     `json:"scope"`
	Description   string     `json:"description"`
	Usage         string     `json:"when_to_use"`
	EnvName       string     `json:"env_name"`
	Masked        string     `json:"-"`
	NeedsApproval bool       `json:"needs_approval"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	valueEnc      []byte
}

func (t *Token) Expired() bool { return t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) }

const tokenCols = `id, name, scope, description, usage, env_name, masked, needs_approval, expires_at, created_at, updated_at, last_used_at, value_enc`

func scanToken(sc interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var exp, last sql.NullInt64
	var created, updated int64
	if err := sc.Scan(&t.ID, &t.Name, &t.Scope, &t.Description, &t.Usage, &t.EnvName, &t.Masked, &t.NeedsApproval, &exp, &created, &updated, &last, &t.valueEnc); err != nil {
		return nil, err
	}
	t.CreatedAt, t.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	t.ExpiresAt, t.LastUsedAt = nullTime(exp), nullTime(last)
	if t.EnvName == "" {
		t.EnvName = defaultEnvName(t.Name)
	}
	return &t, nil
}

// tokens lists tokens, optionally limited to the given scopes (nil = all).
func (db *DB) tokens(scopes []string) ([]*Token, error) {
	q := `SELECT ` + tokenCols + ` FROM tokens`
	var args []any
	if scopes != nil {
		if len(scopes) == 0 {
			return nil, nil
		}
		q += ` WHERE scope IN (?` + strings.Repeat(",?", len(scopes)-1) + `)`
		for _, s := range scopes {
			args = append(args, s)
		}
	}
	rows, err := db.Query(q+` ORDER BY scope, name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) tokenByName(name string) (*Token, error) {
	t, err := scanToken(db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE name=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (db *DB) tokenByID(id int64) (*Token, error) {
	t, err := scanToken(db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

type Login struct {
	ID         int64
	Host       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastSeenAt *time.Time
}

func (l *Login) Active() bool { return l.RevokedAt == nil && time.Now().Before(l.ExpiresAt) }

func (l *Login) HasScope(s string) bool {
	for _, x := range l.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

const loginCols = `id, host, scopes, created_at, expires_at, revoked_at, last_seen_at`

func scanLogin(sc interface{ Scan(...any) error }) (*Login, error) {
	var l Login
	var scopes string
	var created, expires int64
	var revoked, seen sql.NullInt64
	if err := sc.Scan(&l.ID, &l.Host, &scopes, &created, &expires, &revoked, &seen); err != nil {
		return nil, err
	}
	l.Scopes = splitList(scopes)
	l.CreatedAt, l.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	l.RevokedAt, l.LastSeenAt = nullTime(revoked), nullTime(seen)
	return &l, nil
}

func (db *DB) loginByHash(hash string) (*Login, error) {
	l, err := scanLogin(db.QueryRow(`SELECT `+loginCols+` FROM logins WHERE token_hash=?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return l, err
}

func (db *DB) logins() ([]*Login, error) {
	rows, err := db.Query(`SELECT ` + loginCols + ` FROM logins ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Login
	for rows.Next() {
		l, err := scanLogin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

type Event struct {
	ID      int64
	TS      time.Time
	Kind    string
	Token   string
	Scope   string
	LoginID *int64
	Host    string
	Reason  string
	Cwd     string
	Cmd     string
	Agent   string
	Detail  string
}

func (db *DB) logEvent(e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	_, _ = db.Exec(`INSERT INTO events(ts,kind,token,scope,login_id,host,reason,cwd,cmd,agent,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.Kind, e.Token, e.Scope, e.LoginID, e.Host, e.Reason, e.Cwd, e.Cmd, e.Agent, e.Detail)
}

type EventFilter struct {
	Token, Scope, Kind, Host string
	Kinds                    []string
	LoginID                  int64
	Limit                    int
}

func (db *DB) events(f EventFilter) ([]Event, error) {
	q := `SELECT id, ts, kind, token, scope, login_id, host, reason, cwd, cmd, agent, detail FROM events WHERE 1=1`
	var args []any
	for col, v := range map[string]string{"token": f.Token, "scope": f.Scope, "kind": f.Kind, "host": f.Host} {
		if v != "" {
			q += ` AND ` + col + `=?`
			args = append(args, v)
		}
	}
	if len(f.Kinds) > 0 {
		q += ` AND kind IN (?` + strings.Repeat(`,?`, len(f.Kinds)-1) + `)`
		for _, k := range f.Kinds {
			args = append(args, k)
		}
	}
	if f.LoginID != 0 {
		q += ` AND login_id=?`
		args = append(args, f.LoginID)
	}
	if f.Limit == 0 {
		f.Limit = 500
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var lid sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Token, &e.Scope, &lid, &e.Host, &e.Reason, &e.Cwd, &e.Cmd, &e.Agent, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		if lid.Valid {
			e.LoginID = &lid.Int64
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// usedTokens counts existing tokens with at least one use since t.
func (db *DB) usedTokens(since time.Time) (n int) {
	_ = db.QueryRow(`SELECT count(DISTINCT token) FROM events WHERE kind='use' AND ts>=? AND token IN (SELECT name FROM tokens)`, since.Unix()).Scan(&n)
	return n
}

func (db *DB) countEvents(kind string, since time.Time) (n int) {
	_ = db.QueryRow(`SELECT count(*) FROM events WHERE kind=? AND ts>=?`, kind, since.Unix()).Scan(&n)
	return n
}

// dailyUses returns use counts per day for days days ending today; index 0 is the oldest day.
func (db *DB) dailyUses(start time.Time, days int) ([]int, error) {
	out := make([]int, days)
	// chisle: fixed 86400 s buckets, so a DST change shifts one hour of uses into the neighbouring day
	rows, err := db.Query(`SELECT (ts-?)/86400, count(*) FROM events WHERE kind='use' AND ts>=? GROUP BY 1`, start.Unix(), start.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d, n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		if d >= 0 && d < days {
			out[d] = n
		}
	}
	return out, rows.Err()
}

type TokenUse struct {
	Name        string
	Uses, Hosts int
	Last        time.Time
}

func (db *DB) topTokens(since time.Time, limit int) ([]TokenUse, error) {
	rows, err := db.Query(`SELECT token, count(*), count(DISTINCT host), max(ts) FROM events WHERE kind='use' AND ts>=? GROUP BY token ORDER BY 2 DESC, 4 DESC LIMIT ?`, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenUse
	for rows.Next() {
		var u TokenUse
		var last int64
		if err := rows.Scan(&u.Name, &u.Uses, &u.Hosts, &last); err != nil {
			return nil, err
		}
		u.Last = time.Unix(last, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0)
	return &t
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func defaultEnvName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
