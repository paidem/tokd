// tok: client for tokd. Agents list tokens and use them with a stated reason; see `tok help`.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const usage = `tok - use tokens stored in tokd, with a logged reason

  tok login [SERVER_URL]        log this machine in (opens an approval page)
  tok logout                    revoke this machine's login
  tok status                    show server, scopes and login expiry
  tok ls [--json] [--scope S]   list tokens you may use (metadata only)
  tok exec --reason TEXT NAME[=ENV]... -- COMMAND [ARGS]
                                run COMMAND with the tokens in env vars;
                                their values are masked in its output
  tok get --reason TEXT NAME    print a token value (prefer exec); under an
                                agent it needs --reveal, and every reveal
                                needs the owner's approval in the browser
  tok wait REQUEST_ID           block until an approval is decided
  tok version                   print the client version and build time

Every exec/get is logged on the server with the reason, host, directory and
command. Tokens marked "needs approval" print an approval link and exit 3;
open it, approve, then run the same command again (or tok wait first).

Environment: TOK_CONFIG (config file path), TOK_SERVER (default server URL).
`

type config struct {
	Server    string    `json:"server"`
	Token     string    `json:"token"`
	Host      string    `json:"host"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	LoginAt   time.Time `json:"login_at,omitzero"`
}

func configPath() string {
	if p := os.Getenv("TOK_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		d, _ := os.UserConfigDir()
		return filepath.Join(d, "tok", "config.json")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config", "tok", "config.json")
}

func loadConfig() (*config, error) {
	raw, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("not logged in: run `tok login <server-url>`")
	}
	if err != nil {
		return nil, err
	}
	var c config
	return &c, json.Unmarshal(raw, &c)
}

func saveConfig(c *config) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, raw, 0o600)
}

// Set by -ldflags "-X main.version=... -X main.buildTime=...".
var version, buildTime = "dev", ""

func versionLine() string {
	if buildTime == "" {
		return "tok " + version
	}
	return "tok " + version + ", built " + buildTime
}

// loginLine describes the saved login from the config file alone (no network).
func loginLine() string {
	c, err := loadConfig()
	switch {
	case err != nil || c.Token == "":
		return "Not logged in. Run: tok login <server-url>"
	case time.Now().After(c.ExpiresAt):
		return fmt.Sprintf("Login to %s expired %s. Run: tok login", c.Server, c.ExpiresAt.Local().Format("2006-01-02 15:04"))
	}
	since := ""
	if !c.LoginAt.IsZero() {
		since = ", logged in " + c.LoginAt.Local().Format("2006-01-02 15:04")
	}
	return fmt.Sprintf("Logged in to %s as %s (scopes %s)%s, expires %s.", c.Server, c.Host, strings.Join(c.Scopes, ","),
		since, c.ExpiresAt.Local().Format("2006-01-02 15:04"))
}

var httpc = &http.Client{Timeout: 30 * time.Second}

type apiError struct {
	Code int
	Msg  string
	Body map[string]any
}

func (e *apiError) Error() string { return e.Msg }

func call(c *config, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.Server, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 || resp.StatusCode == http.StatusAccepted {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		msg, _ := m["error"].(string)
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &apiError{Code: resp.StatusCode, Msg: msg, Body: m}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("%s\n%s\n\n%s", versionLine(), loginLine(), usage)
		return
	}
	var err error
	code := 0
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "login":
		err = cmdLogin(args)
	case "logout":
		err = cmdLogout()
	case "status", "whoami":
		err = cmdStatus()
	case "ls", "list":
		err = cmdList(args)
	case "get":
		err = cmdGet(args)
	case "exec", "run":
		code, err = cmdExec(args)
	case "wait":
		err = cmdWait(args)
	case "version", "--version":
		fmt.Println(versionLine())
		return
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q (see tok help)", cmd)
	}
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Code == http.StatusAccepted {
			code = 3
		}
		fmt.Fprintln(os.Stderr, "tok:", err)
		os.Exit(max(code, 1))
	}
	os.Exit(code)
}

// opts is a tiny flag parser that allows flags after positional args (tok get NAME --reason x).
type opts struct {
	reason, scope, timeout string
	json, noRedact, reveal bool
	pos, rest              []string
}

func parse(args []string) (*opts, error) {
	o := &opts{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") {
				return v, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch name, _, _ := strings.Cut(a, "="); name {
		case "--":
			o.rest = args[i+1:]
			return o, nil
		case "-r", "--reason":
			o.reason, err = val()
		case "--scope":
			o.scope, err = val()
		case "--timeout":
			o.timeout, err = val()
		case "--json":
			o.json = true
		case "--no-redact":
			o.noRedact = true
		case "--reveal":
			o.reveal = true
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown flag %s", a)
			}
			o.pos = append(o.pos, a)
		}
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.TrimSuffix(h, ".local")
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = c.Start()
}

func cmdLogin(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	server := os.Getenv("TOK_SERVER")
	if old, err := loadConfig(); err == nil && old.Server != "" {
		server = old.Server
	}
	if len(o.pos) > 0 {
		server = o.pos[0]
	}
	if server == "" {
		return errors.New("usage: tok login <server-url>, e.g. tok login http://localhost:19191")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	c := &config{Server: strings.TrimRight(server, "/"), Host: hostname()}
	var start struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		VerifyURL  string `json:"verify_url"`
		Interval   int    `json:"interval"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := call(c, "POST", "/api/device/start", map[string]string{"host": c.Host}, &start); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Approve this login in the browser:\n\n  %s\n\nCode: %s (check it matches the page)\nWaiting...\n", start.VerifyURL, start.UserCode)
	if isTerminal(os.Stderr) {
		openBrowser(start.VerifyURL)
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(max(start.Interval, 1)) * time.Second)
		var res struct {
			Token     string    `json:"token"`
			Host      string    `json:"host"`
			Scopes    []string  `json:"scopes"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		err := call(c, "POST", "/api/device/poll", map[string]string{"device_code": start.DeviceCode}, &res)
		var ae *apiError
		if errors.As(err, &ae) && ae.Code == http.StatusPreconditionRequired {
			continue
		}
		if err != nil {
			return err
		}
		c.Token, c.Scopes, c.ExpiresAt, c.LoginAt = res.Token, res.Scopes, res.ExpiresAt, time.Now()
		if err := saveConfig(c); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Logged in as %s, scopes %s, until %s.\n", c.Host, strings.Join(c.Scopes, ","), c.ExpiresAt.Local().Format("2006-01-02 15:04"))
		return nil
	}
	return errors.New("login not approved in time")
}

func cmdLogout() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if err := call(c, "POST", "/api/logout", nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "tok: server logout failed:", err)
	}
	c.Token = ""
	return saveConfig(c)
}

func cmdStatus() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	var who struct {
		LoginID   int64     `json:"login_id"`
		Host      string    `json:"host"`
		Scopes    []string  `json:"scopes"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := call(c, "GET", "/api/whoami", nil, &who); err != nil {
		return err
	}
	fmt.Printf("server  %s\nlogin   #%d as %s\nscopes  %s\n", c.Server, who.LoginID, who.Host, strings.Join(who.Scopes, ", "))
	if !who.CreatedAt.IsZero() { // older servers don't send it
		fmt.Printf("since   %s\n", who.CreatedAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Printf("expires %s (in %s)\n", who.ExpiresAt.Local().Format("2006-01-02 15:04"), time.Until(who.ExpiresAt).Round(time.Minute))
	return nil
}

type tokenInfo struct {
	Name          string     `json:"name"`
	Scope         string     `json:"scope"`
	Description   string     `json:"description"`
	WhenToUse     string     `json:"when_to_use"`
	EnvName       string     `json:"env_name"`
	NeedsApproval bool       `json:"needs_approval"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Expired       bool       `json:"expired,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

func cmdList(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	var res struct {
		Scopes []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"scopes"`
		Tokens []tokenInfo `json:"tokens"`
	}
	if err := call(c, "GET", "/api/tokens", nil, &res); err != nil {
		return err
	}
	if o.scope != "" {
		var f []tokenInfo
		for _, t := range res.Tokens {
			if t.Scope == o.scope {
				f = append(f, t)
			}
		}
		res.Tokens = f
	}
	if o.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	sort.SliceStable(res.Tokens, func(i, j int) bool { return res.Tokens[i].Scope < res.Tokens[j].Scope })
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSCOPE\tENV\tADDED\tLAST USED\tFLAGS\tDESCRIPTION")
	for _, t := range res.Tokens {
		var flags []string
		if t.NeedsApproval {
			flags = append(flags, "approval")
		}
		if t.Expired {
			flags = append(flags, "EXPIRED")
		} else if t.ExpiresAt != nil {
			flags = append(flags, "exp "+t.ExpiresAt.Local().Format("2006-01-02"))
		}
		last := "never"
		if t.LastUsedAt != nil {
			last = t.LastUsedAt.Local().Format("2006-01-02")
		}
		desc := t.Description
		if t.WhenToUse != "" {
			desc += " | use: " + t.WhenToUse
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.Scope, t.EnvName, t.CreatedAt.Local().Format("2006-01-02"), last,
			strings.Join(flags, ","), strings.ReplaceAll(desc, "\n", " "))
	}
	return w.Flush()
}

// agentEnv names the first environment variable showing tok runs under an AI agent, or "".
// T3CODE_THREAD_ID is left out: it identifies the host app, which also runs human terminals.
func agentEnv() string {
	for _, k := range []string{"AI_AGENT", "CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"} {
		if os.Getenv(k) != "" {
			return k
		}
	}
	return ""
}

func agentInfo() string {
	var parts []string
	for _, k := range []string{"AI_AGENT", "CLAUDE_CODE_SESSION_ID", "T3CODE_THREAD_ID", "CODEX_THREAD_ID"} {
		if v := os.Getenv(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

type useResult struct {
	Name    string `json:"name"`
	EnvName string `json:"env_name"`
	Value   string `json:"value"`
}

// use fetches one value; on "approval required" it waits when a human is at the terminal,
// otherwise it returns the 202 error so the agent can show the link and retry.
// revealWait stays under the ~2 minute command timeout of agent shells.
const revealWait = 100 * time.Second

// use fetches a value. reveal marks that it will be shown to an agent: the server then always asks
// the owner, so tok opens the approval page and waits briefly instead of only printing the link.
func use(c *config, name, reason, cmdline string, reveal bool) (*useResult, error) {
	cwd, _ := os.Getwd()
	req := map[string]any{"name": name, "reason": reason, "cwd": cwd, "cmd": cmdline, "agent": agentInfo(), "reveal": reveal}
	for {
		var res useResult
		err := call(c, "POST", "/api/use", req, &res)
		var ae *apiError
		if !errors.As(err, &ae) || ae.Code != http.StatusAccepted {
			return &res, err
		}
		url, _ := ae.Body["approve_url"].(string)
		id, _ := ae.Body["request_id"].(string)
		if reveal {
			if reused, _ := ae.Body["reused"].(bool); !reused {
				openBrowser(url)
			}
			fmt.Fprintf(os.Stderr, "tok: showing %q to an agent needs the owner's approval: %s\ntok: waiting up to %s...\n", name, url, revealWait)
			if err := waitFor(c, id, revealWait); err != nil {
				if strings.HasPrefix(err.Error(), "request ") { // denied or expired
					return nil, err
				}
				return nil, &apiError{Code: http.StatusAccepted, Msg: fmt.Sprintf(
					"revealing %q needs approval. Ask the user to approve it in the opened tab (%s), then rerun this command.", name, url)}
			}
			continue
		}
		if !isTerminal(os.Stdin) || os.Getenv("CLAUDECODE") != "" || os.Getenv("AI_AGENT") != "" {
			return nil, &apiError{Code: http.StatusAccepted, Msg: fmt.Sprintf(
				"token %q needs approval. Show the user this link and ask them to approve:\n  %s\nThen run `tok wait %s` (blocks up to 10 min) or simply rerun this command after they confirm.",
				name, url, id)}
		}
		fmt.Fprintf(os.Stderr, "tok: %q needs approval: %s\n", name, url)
		openBrowser(url)
		if err := waitFor(c, id, 10*time.Minute); err != nil {
			return nil, err
		}
	}
}

func waitFor(c *config, id string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var st struct {
			Status string `json:"status"`
		}
		if err := call(c, "GET", "/api/requests/"+id, nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "approved":
			return nil
		case "denied", "expired":
			return fmt.Errorf("request %s", st.Status)
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("still waiting for approval; rerun when approved")
}

func cmdWait(args []string) error {
	o, err := parse(args)
	if err != nil || len(o.pos) != 1 {
		return errors.New("usage: tok wait REQUEST_ID [--timeout 10m]")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	d := 10 * time.Minute
	if o.timeout != "" {
		if d, err = time.ParseDuration(o.timeout); err != nil {
			return err
		}
	}
	if err := waitFor(c, o.pos[0], d); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "tok: approved; rerun your command now")
	return nil
}

func cmdGet(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if len(o.pos) != 1 || o.reason == "" {
		return errors.New(`usage: tok get --reason "why you need it" NAME`)
	}
	// Under an agent the printed value lands in the model's context, and output redaction
	// (e.g. secret-guard) only catches values with a recognisable shape. exec keeps it out.
	if v := agentEnv(); v != "" && !o.reveal {
		return fmt.Errorf("tok get prints the secret into the agent's output (%s is set). "+
			"Use tok exec instead: the value goes into the command's environment and is masked in its output. "+
			"If the user explicitly asked for the raw value, add --reveal", v)
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	cmdline := "tok get " + o.pos[0]
	if o.reveal {
		cmdline = "tok get --reveal " + o.pos[0]
	}
	res, err := use(c, o.pos[0], o.reason, cmdline, o.reveal && agentEnv() != "")
	if err != nil {
		return err
	}
	fmt.Println(res.Value)
	return nil
}

func cmdExec(args []string) (int, error) {
	o, err := parse(args)
	if err != nil {
		return 1, err
	}
	if len(o.pos) == 0 || len(o.rest) == 0 || o.reason == "" {
		return 1, errors.New(`usage: tok exec --reason "why" NAME[=ENV_VAR]... -- command [args]`)
	}
	c, err := loadConfig()
	if err != nil {
		return 1, err
	}
	cmdline := strings.Join(o.rest, " ")
	env := os.Environ()
	var secrets []string
	for _, spec := range o.pos {
		name, envName, _ := strings.Cut(spec, "=")
		res, err := use(c, name, o.reason, cmdline, o.noRedact && agentEnv() != "")
		if err != nil {
			return 1, err
		}
		if envName == "" {
			envName = res.EnvName
		}
		env = append(env, envName+"="+res.Value)
		secrets = append(secrets, res.Value)
	}
	cmd := exec.Command(o.rest[0], o.rest[1:]...)
	cmd.Env, cmd.Stdin = env, os.Stdin
	if o.noRedact {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	} else {
		out, errw := newRedactor(os.Stdout, secrets), newRedactor(os.Stderr, secrets)
		defer out.Flush()
		defer errw.Flush()
		cmd.Stdout, cmd.Stderr = out, errw
	}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 127, err
	}
	return 0, nil
}
