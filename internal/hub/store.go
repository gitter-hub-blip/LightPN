package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the hub SQLite database. Per design invariant 4 it holds only
// the node registry, IP assignments, links, tokens and admin accounts.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  overlay_ip  TEXT NOT NULL UNIQUE,
  cert_serial TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER,
  revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS links (
  id          TEXT PRIMARY KEY,
  a           TEXT NOT NULL REFERENCES nodes(id),
  b           TEXT NOT NULL REFERENCES nodes(id),
  created_at  INTEGER NOT NULL,
  exit_node   TEXT NOT NULL DEFAULT '',   -- '' = no exit; else the node that egresses to the internet
  UNIQUE(a, b)
);
CREATE TABLE IF NOT EXISTS tokens (
  id          TEXT PRIMARY KEY,
  hash        TEXT NOT NULL,
  note        TEXT,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE TABLE IF NOT EXISTS admins (
  id          TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  pw_hash     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_cooldown (
  overlay_ip  TEXT PRIMARY KEY,
  freed_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS exitwg (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id),
  enabled INTEGER NOT NULL DEFAULT 0,
  port    INTEGER NOT NULL,
  cidr    TEXT NOT NULL,
  pubkey  TEXT NOT NULL DEFAULT ''    -- agent's persistent server pubkey, from exitwg_status
);
CREATE TABLE IF NOT EXISTS exitwg_peers (
  id         TEXT PRIMARY KEY,
  node_id    TEXT NOT NULL REFERENCES nodes(id),
  name       TEXT NOT NULL,
  pubkey     TEXT NOT NULL,
  ip         TEXT NOT NULL,           -- client /32 within the node's exitwg cidr
  created_at INTEGER NOT NULL,
  UNIQUE(node_id, pubkey),
  UNIQUE(node_id, ip)
);
`

// OpenStore opens (and migrates) the SQLite database at path.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc sqlite: serialize writers
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate applies additive schema changes for databases created by an
// earlier version. Each step is idempotent.
func migrate(db *sql.DB) error {
	// links.exit_node (added in the exit-node feature).
	if !hasColumn(db, "links", "exit_node") {
		if _, err := db.Exec(`ALTER TABLE links ADD COLUMN exit_node TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && name == col {
			return true
		}
	}
	return false
}

func (s *Store) Close() error { return s.db.Close() }

// NewULID returns a new ULID string.
func NewULID() string { return ulid.Make().String() }

// ---- nodes ----

type Node struct {
	ID         string
	Name       string
	OverlayIP  string // bare IP, no prefix
	CertSerial string
	CreatedAt  int64
	LastSeen   int64
	Revoked    bool
}

func (s *Store) CreateNode(n *Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes (id,name,overlay_ip,cert_serial,created_at,last_seen,revoked) VALUES (?,?,?,?,?,?,0)`,
		n.ID, n.Name, n.OverlayIP, n.CertSerial, n.CreatedAt, n.LastSeen)
	return err
}

func (s *Store) GetNode(id string) (*Node, error) {
	row := s.db.QueryRow(`SELECT id,name,overlay_ip,cert_serial,created_at,COALESCE(last_seen,0),revoked FROM nodes WHERE id=?`, id)
	return scanNode(row)
}

func scanNode(row *sql.Row) (*Node, error) {
	var n Node
	var revoked int
	err := row.Scan(&n.ID, &n.Name, &n.OverlayIP, &n.CertSerial, &n.CreatedAt, &n.LastSeen, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.Revoked = revoked != 0
	return &n, nil
}

func (s *Store) ListNodes() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT id,name,overlay_ip,cert_serial,created_at,COALESCE(last_seen,0),revoked FROM nodes WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		var n Node
		var revoked int
		if err := rows.Scan(&n.ID, &n.Name, &n.OverlayIP, &n.CertSerial, &n.CreatedAt, &n.LastSeen, &revoked); err != nil {
			return nil, err
		}
		n.Revoked = revoked != 0
		out = append(out, &n)
	}
	return out, rows.Err()
}

func (s *Store) RenameNode(id, name string) error {
	res, err := s.db.Exec(`UPDATE nodes SET name=? WHERE id=? AND revoked=0`, name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchNode(id string, ts int64) error {
	_, err := s.db.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, ts, id)
	return err
}

// DeleteNode removes the node and its links, and parks its IP in the
// cooldown pool. Returns the removed links' IDs and peers.
func (s *Store) DeleteNode(id string, now int64) (*Node, []*Link, error) {
	node, err := s.GetNode(id)
	if err != nil {
		return nil, nil, err
	}
	links, err := s.LinksOfNode(id)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM links WHERE a=? OR b=?`, id, id); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(`DELETE FROM exitwg_peers WHERE node_id=?`, id); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(`DELETE FROM exitwg WHERE node_id=?`, id); err != nil {
		return nil, nil, err
	}
	// The revoked row is kept only for the cert revocation list; free its
	// overlay IP (the UNIQUE column) so the cooldown pool governs reuse.
	if _, err := tx.Exec(`UPDATE nodes SET revoked=1, overlay_ip='freed:'||id WHERE id=?`, id); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO ip_cooldown (overlay_ip,freed_at) VALUES (?,?)`, node.OverlayIP, now); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return node, links, nil
}

// RevokedSerials returns all revoked certificate serials (for the in-memory
// revocation list rebuilt at startup).
func (s *Store) RevokedSerials() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT cert_serial FROM nodes WHERE revoked=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, err
		}
		out[serial] = true
	}
	return out, rows.Err()
}

func (s *Store) UpdateCertSerial(id, serial string) error {
	_, err := s.db.Exec(`UPDATE nodes SET cert_serial=? WHERE id=?`, serial, id)
	return err
}

// ---- IPAM ----

// AllocateIP picks the lowest free host address in cidr, honoring the
// cooldown pool. .0/.255 (network/broadcast) and .1 (reserved for hub) are
// never allocated.
func (s *Store) AllocateIP(cidr string, cooldown time.Duration, now int64) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	rows, err := s.db.Query(`SELECT overlay_ip FROM nodes WHERE revoked=0`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return "", err
		}
		used[ip] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	// Expire cooldowns, then treat remaining ones as used.
	cutoff := now - int64(cooldown.Seconds())
	if _, err := s.db.Exec(`DELETE FROM ip_cooldown WHERE freed_at < ?`, cutoff); err != nil {
		return "", err
	}
	rows, err = s.db.Query(`SELECT overlay_ip FROM ip_cooldown`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return "", err
		}
		used[ip] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}

	network := prefix.Masked().Addr()
	broadcast := lastAddr(prefix)
	for ip := network.Next(); prefix.Contains(ip); ip = ip.Next() {
		if ip == broadcast {
			break
		}
		if ip == network.Next() { // .1 reserved for hub
			continue
		}
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", errors.New("IPAM exhausted")
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	for i := bits; i < 32; i++ {
		a[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(a)
}

// ---- links ----

type Link struct {
	ID        string
	A, B      string
	CreatedAt int64
	// ExitNode is empty for a plain link, or the node ID (== A or B) that
	// serves as the internet egress for the other end.
	ExitNode string
}

// CreateLink stores a link with (a,b) sorted for dedup.
func (s *Store) CreateLink(a, b string, now int64) (*Link, error) {
	if a == b {
		return nil, errors.New("cannot link a node to itself")
	}
	pair := []string{a, b}
	sort.Strings(pair)
	l := &Link{ID: NewULID(), A: pair[0], B: pair[1], CreatedAt: now}
	_, err := s.db.Exec(`INSERT INTO links (id,a,b,created_at,exit_node) VALUES (?,?,?,?,'')`, l.ID, l.A, l.B, l.CreatedAt)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// SetLinkExit sets (or clears, with exitNode="") which end egresses to the
// internet for a link. exitNode must be one of the link's endpoints.
func (s *Store) SetLinkExit(id, exitNode string) (*Link, error) {
	l, err := s.GetLink(id)
	if err != nil {
		return nil, err
	}
	if exitNode != "" && exitNode != l.A && exitNode != l.B {
		return nil, errors.New("exit node must be one of the link's endpoints")
	}
	if _, err := s.db.Exec(`UPDATE links SET exit_node=? WHERE id=?`, exitNode, id); err != nil {
		return nil, err
	}
	l.ExitNode = exitNode
	return l, nil
}

func (s *Store) GetLink(id string) (*Link, error) {
	var l Link
	err := s.db.QueryRow(`SELECT id,a,b,created_at,exit_node FROM links WHERE id=?`, id).Scan(&l.ID, &l.A, &l.B, &l.CreatedAt, &l.ExitNode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) DeleteLink(id string) error {
	res, err := s.db.Exec(`DELETE FROM links WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListLinks() ([]*Link, error) {
	rows, err := s.db.Query(`SELECT id,a,b,created_at,exit_node FROM links ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.ID, &l.A, &l.B, &l.CreatedAt, &l.ExitNode); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *Store) LinksOfNode(id string) ([]*Link, error) {
	rows, err := s.db.Query(`SELECT id,a,b,created_at,exit_node FROM links WHERE a=? OR b=?`, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.ID, &l.A, &l.B, &l.CreatedAt, &l.ExitNode); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

// Other returns the peer node ID of a link from the perspective of id.
func (l *Link) Other(id string) string {
	if l.A == id {
		return l.B
	}
	return l.A
}

// ---- tokens ----

type Token struct {
	ID        string
	Note      string
	ExpiresAt int64
	UsedAt    int64
	Prefix    string // display only
}

var tokenEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// CreateToken mints a one-time enrollment token. The plaintext is returned
// exactly once; only its SHA-256 is stored.
func (s *Store) CreateToken(ttl time.Duration, note string, now int64) (plaintext string, tok *Token, err error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	plaintext = "lp_" + tokenEnc.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	tok = &Token{ID: NewULID(), Note: note, ExpiresAt: now + int64(ttl.Seconds())}
	_, err = s.db.Exec(`INSERT INTO tokens (id,hash,note,expires_at) VALUES (?,?,?,?)`,
		tok.ID, hex.EncodeToString(sum[:]), note, tok.ExpiresAt)
	if err != nil {
		return "", nil, err
	}
	tok.Prefix = plaintext[:8]
	return plaintext, tok, nil
}

// ConsumeToken validates and burns a token. Returns proto-level error codes
// via sentinel errors.
var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenUsed    = errors.New("token already used")
)

func (s *Store) ConsumeToken(plaintext string, now int64) error {
	sum := sha256.Sum256([]byte(plaintext))
	h := hex.EncodeToString(sum[:])
	var id string
	var expiresAt int64
	var usedAt sql.NullInt64
	err := s.db.QueryRow(`SELECT id,expires_at,used_at FROM tokens WHERE hash=?`, h).Scan(&id, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if usedAt.Valid {
		return ErrTokenUsed
	}
	if now > expiresAt {
		return ErrTokenExpired
	}
	res, err := s.db.Exec(`UPDATE tokens SET used_at=? WHERE id=? AND used_at IS NULL`, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTokenUsed // raced with a concurrent enroll
	}
	return nil
}

func (s *Store) ListTokens(now int64) ([]*Token, error) {
	rows, err := s.db.Query(`SELECT id,COALESCE(note,''),expires_at FROM tokens WHERE used_at IS NULL AND expires_at > ? ORDER BY expires_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Note, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteToken(id string) error {
	res, err := s.db.Exec(`DELETE FROM tokens WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- admins ----

func (s *Store) SetAdmin(username, pwHash string) error {
	_, err := s.db.Exec(`INSERT INTO admins (id,username,pw_hash) VALUES (?,?,?)
		ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash`, NewULID(), username, pwHash)
	return err
}

func (s *Store) GetAdminHash(username string) (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT pw_hash FROM admins WHERE username=?`, username).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// HasAdmin reports whether any admin account exists.
func (s *Store) HasAdmin() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	return n > 0, err
}
