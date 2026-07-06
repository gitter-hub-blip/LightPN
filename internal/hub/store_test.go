package hub

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestIPAMSkipsReserved(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	ip, err := s.AllocateIP("100.100.0.0/24", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// .0 network, .1 hub-reserved → first allocation must be .2
	if ip != "100.100.0.2" {
		t.Fatalf("first IP = %s, want 100.100.0.2", ip)
	}
}

func TestIPAMSequentialAndCooldown(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	ip1, _ := s.AllocateIP("100.100.0.0/29", time.Hour, now)
	if err := s.CreateNode(&Node{ID: "n1", Name: "n1", OverlayIP: ip1, CertSerial: "s1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	ip2, _ := s.AllocateIP("100.100.0.0/29", time.Hour, now)
	if ip2 == ip1 {
		t.Fatalf("allocated duplicate IP %s", ip2)
	}
	// Delete n1: its IP must stay in cooldown …
	if _, _, err := s.DeleteNode("n1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(&Node{ID: "n2", Name: "n2", OverlayIP: ip2, CertSerial: "s2", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	ip3, err := s.AllocateIP("100.100.0.0/29", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if ip3 == ip1 {
		t.Fatalf("cooldown violated: %s reused immediately", ip1)
	}
	// … but is reusable after the cooldown expires.
	ip4, err := s.AllocateIP("100.100.0.0/29", time.Hour, now+7200)
	if err != nil {
		t.Fatal(err)
	}
	if ip4 != ip1 {
		t.Fatalf("expected %s after cooldown, got %s", ip1, ip4)
	}
}

func TestIPAMExhaustion(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	// /30: .0 network, .1 reserved, .2 usable, .3 broadcast → 1 address
	ip, err := s.AllocateIP("100.100.0.0/30", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateNode(&Node{ID: "n1", Name: "n1", OverlayIP: ip, CertSerial: "s", CreatedAt: now})
	if _, err := s.AllocateIP("100.100.0.0/30", time.Hour, now); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

func TestTokenLifecycle(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	plaintext, _, err := s.CreateToken(15*time.Minute, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeToken(plaintext, now); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := s.ConsumeToken(plaintext, now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume = %v, want ErrTokenUsed", err)
	}
	// expired token
	p2, _, _ := s.CreateToken(time.Minute, "short", now)
	if err := s.ConsumeToken(p2, now+120); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired consume = %v, want ErrTokenExpired", err)
	}
	// unknown token
	if err := s.ConsumeToken("lp_nonexistent", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown consume = %v, want ErrNotFound", err)
	}
}

func TestLinkDedup(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	for _, id := range []string{"na", "nb"} {
		s.CreateNode(&Node{ID: id, Name: id, OverlayIP: "100.100.0." + id, CertSerial: "s", CreatedAt: now})
	}
	if _, err := s.CreateLink("nb", "na", now); err != nil {
		t.Fatal(err)
	}
	// Same pair in either order must violate UNIQUE(a,b).
	if _, err := s.CreateLink("na", "nb", now); err == nil {
		t.Fatal("expected duplicate link rejection")
	}
	if _, err := s.CreateLink("na", "na", now); err == nil {
		t.Fatal("expected self-link rejection")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("invalid password accepted")
	}
}
