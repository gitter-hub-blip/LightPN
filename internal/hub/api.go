package hub

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/argon2"
)

//go:embed web
var webFS embed.FS

// ---- password hashing (argon2id) ----

// HashPassword produces an argon2id PHC-format hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return "$argon2id$v=19$m=65536,t=3,p=2$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// VerifyPassword checks a password against a PHC argon2id hash.
func VerifyPassword(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmtSscanParams(parts[3], &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func fmtSscanParams(s string, m, t *uint32, p *uint8) (int, error) {
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, errors.New("bad params")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, err
		}
		switch k {
		case "m":
			*m = uint32(n)
		case "t":
			*t = uint32(n)
		case "p":
			*p = uint8(n)
		}
	}
	return 3, nil
}

// ---- API server ----

type apiServer struct {
	hub *Hub
	log *slog.Logger

	sessMu   sync.Mutex
	sessions map[string]time.Time // session token -> expiry

	loginMu    sync.Mutex
	loginTries map[string][]time.Time // ip -> recent attempts
}

const sessionTTL = 12 * time.Hour

// ServeAPI runs the admin HTTP API + panel on cfg.APIAddr (loopback).
func (h *Hub) ServeAPI(stop <-chan struct{}) error {
	a := &apiServer{
		hub:        h,
		log:        h.Log,
		sessions:   map[string]time.Time{},
		loginTries: map[string][]time.Time{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)
	mux.Handle("GET /api/nodes", a.auth(a.listNodes))
	mux.Handle("GET /api/nodes/{id}", a.auth(a.getNode))
	mux.Handle("GET /api/nodes/{id}/metrics", a.auth(a.nodeMetrics))
	mux.Handle("PATCH /api/nodes/{id}", a.auth(a.patchNode))
	mux.Handle("DELETE /api/nodes/{id}", a.auth(a.deleteNode))
	mux.Handle("POST /api/nodes/{id}/rotate-wg", a.auth(a.rotateWG))
	mux.Handle("POST /api/tokens", a.auth(a.createToken))
	mux.Handle("GET /api/tokens", a.auth(a.listTokens))
	mux.Handle("DELETE /api/tokens/{id}", a.auth(a.deleteToken))
	mux.Handle("GET /api/links", a.auth(a.listLinks))
	mux.Handle("POST /api/links", a.auth(a.createLink))
	mux.Handle("PATCH /api/links/{id}", a.auth(a.setLinkExit))
	mux.Handle("DELETE /api/links/{id}", a.auth(a.deleteLink))
	mux.Handle("GET /api/ws", a.auth(a.ws))
	mux.Handle("GET /api/session", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
	}))

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{Addr: h.Cfg.APIAddr, Handler: mux}
	go func() {
		<-stop
		srv.Close()
	}()
	h.Log.Info("admin API listening", "addr", h.Cfg.APIAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---- auth ----

func (a *apiServer) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("lp_session")
		if err != nil || !a.sessionValid(c.Value) {
			httpErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		next(w, r)
	})
}

func (a *apiServer) sessionValid(tok string) bool {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sessions[tok]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, tok)
		return false
	}
	return true
}

func (a *apiServer) loginAllowed(ip string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	now := time.Now()
	kept := a.loginTries[ip][:0]
	for _, t := range a.loginTries[ip] {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 5 {
		a.loginTries[ip] = kept
		return false
	}
	a.loginTries[ip] = append(kept, now)
	return true
}

func (a *apiServer) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !a.loginAllowed(ip) {
		httpErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request")
		return
	}
	hash, err := a.hub.Store.GetAdminHash(body.Username)
	if err != nil || !VerifyPassword(body.Password, hash) {
		httpErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	a.sessMu.Lock()
	a.sessions[tok] = time.Now().Add(sessionTTL)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "lp_session", Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *apiServer) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("lp_session"); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, c.Value)
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "lp_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- nodes ----

type nodeJSON struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	OverlayIP    string  `json:"overlay_ip"`
	Status       string  `json:"status"`
	Endpoint     string  `json:"endpoint"`
	AgentVersion string  `json:"agent_version"`
	LastSeen     int64   `json:"last_seen"`
	ExitCapable  bool    `json:"exit_capable"`
	SysSummary   *Sample `json:"sys_summary,omitempty"`
}

func (a *apiServer) nodeJSON(n *Node) nodeJSON {
	out := nodeJSON{
		ID: n.ID, Name: n.Name, OverlayIP: n.OverlayIP,
		Status: a.hub.NodeStatus(n.ID), LastSeen: n.LastSeen,
	}
	if info, ok := a.hub.Session(n.ID); ok {
		out.Endpoint = info.Endpoint
		out.AgentVersion = info.AgentVersion
		out.LastSeen = info.LastHB
		out.ExitCapable = info.ExitCapable
	}
	if s, ok := a.hub.Metrics.Latest(n.ID); ok {
		out.SysSummary = &s
	}
	return out
}

func (a *apiServer) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.hub.Store.ListNodes()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []nodeJSON{}
	for _, n := range nodes {
		out = append(out, a.nodeJSON(n))
	}
	writeJSON(w, out)
}

func (a *apiServer) getNode(w http.ResponseWriter, r *http.Request) {
	n, err := a.hub.Store.GetNode(r.PathValue("id"))
	if err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	out := struct {
		nodeJSON
		Peers any `json:"peers"`
	}{nodeJSON: a.nodeJSON(n)}
	if info, ok := a.hub.Session(n.ID); ok {
		out.Peers = info.WGPeers
	}
	writeJSON(w, out)
}

func (a *apiServer) nodeMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rangeS := parseRange(r.URL.Query().Get("range"), time.Hour)
	now := time.Now().Unix()
	samples := a.hub.Metrics.Range(id, now-int64(rangeS.Seconds()), now)
	out := struct {
		TS   []int64   `json:"ts"`
		CPU  []float64 `json:"cpu"`
		Mem  []float64 `json:"mem"`
		Disk []float64 `json:"disk"`
		Rx   []float64 `json:"rx_rate"`
		Tx   []float64 `json:"tx_rate"`
	}{TS: []int64{}, CPU: []float64{}, Mem: []float64{}, Disk: []float64{}, Rx: []float64{}, Tx: []float64{}}
	for _, s := range samples {
		if s.TS == 0 {
			continue
		}
		out.TS = append(out.TS, s.TS)
		out.CPU = append(out.CPU, s.CPUPct)
		out.Mem = append(out.Mem, s.MemPct)
		out.Disk = append(out.Disk, s.DiskPct)
		out.Rx = append(out.Rx, s.RxRate)
		out.Tx = append(out.Tx, s.TxRate)
	}
	writeJSON(w, out)
}

func parseRange(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > 24*time.Hour {
		return def
	}
	return d
}

func (a *apiServer) patchNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		httpErr(w, http.StatusBadRequest, "name required")
		return
	}
	if err := a.hub.Store.RenameNode(r.PathValue("id"), strings.TrimSpace(body.Name)); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *apiServer) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := a.hub.DeleteNode(r.PathValue("id")); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *apiServer) rotateWG(w http.ResponseWriter, r *http.Request) {
	if err := a.hub.RotateWG(r.PathValue("id")); err != nil {
		httpErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- tokens ----

func (a *apiServer) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTLs int    `json:"ttl_s"`
		Note string `json:"note"`
	}
	json.NewDecoder(r.Body).Decode(&body) // empty body OK
	ttl := a.hub.Cfg.TokenTTL()
	if body.TTLs > 0 && body.TTLs <= 24*3600 {
		ttl = time.Duration(body.TTLs) * time.Second
	}
	plaintext, tok, err := a.hub.Store.CreateToken(ttl, body.Note, time.Now().Unix())
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"id": tok.ID, "token": plaintext, "expires_at": tok.ExpiresAt,
	})
}

func (a *apiServer) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.hub.Store.ListTokens(time.Now().Unix())
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []map[string]any{}
	for _, t := range toks {
		out = append(out, map[string]any{
			"id": t.ID, "note": t.Note, "expires_at": t.ExpiresAt,
		})
	}
	writeJSON(w, out)
}

func (a *apiServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if err := a.hub.Store.DeleteToken(r.PathValue("id")); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- links ----

func (a *apiServer) listLinks(w http.ResponseWriter, r *http.Request) {
	links, err := a.hub.Store.ListLinks()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []map[string]any{}
	for _, l := range links {
		hs, rx, tx := a.hub.LinkRuntime(l.ID)
		out = append(out, map[string]any{
			"id": l.ID, "a": l.A, "b": l.B,
			"status":         a.hub.LinkStatus(l),
			"created_at":     l.CreatedAt,
			"exit_node":      l.ExitNode,
			"last_handshake": hs,
			"rx_rate":        rx,
			"tx_rate":        tx,
		})
	}
	writeJSON(w, out)
}

// setLinkExit handles PATCH /api/links/{id} { "exit_node": "<nodeID>|"" }.
func (a *apiServer) setLinkExit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExitNode string `json:"exit_node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request")
		return
	}
	l, err := a.hub.SetLinkExit(r.PathValue("id"), body.ExitNode)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpErr(w, http.StatusNotFound, "not found")
			return
		}
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"id": l.ID, "exit_node": l.ExitNode, "status": a.hub.LinkStatus(l)})
}

func (a *apiServer) createLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.A == "" || body.B == "" {
		httpErr(w, http.StatusBadRequest, "a and b node ids required")
		return
	}
	// Both nodes must exist and not be revoked.
	for _, id := range []string{body.A, body.B} {
		if n, err := a.hub.Store.GetNode(id); err != nil || n.Revoked {
			httpErr(w, http.StatusBadRequest, "unknown node "+id)
			return
		}
	}
	l, err := a.hub.CreateLink(body.A, body.B)
	if err != nil {
		httpErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, map[string]any{"id": l.ID, "a": l.A, "b": l.B, "status": a.hub.LinkStatus(l)})
}

func (a *apiServer) deleteLink(w http.ResponseWriter, r *http.Request) {
	if err := a.hub.DeleteLink(r.PathValue("id")); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- websocket fanout ----

var upgrader = websocket.Upgrader{
	// API is loopback-only behind Cloudflare Access; the session cookie
	// already gates this endpoint.
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (a *apiServer) ws(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	events, cancel := a.hub.Subscribe()
	defer cancel()
	// Reader goroutine: only to detect close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		case ev := <-events:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		}
	}
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func httpNotFoundOr500(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "not found")
		return
	}
	httpErr(w, http.StatusInternalServerError, err.Error())
}
