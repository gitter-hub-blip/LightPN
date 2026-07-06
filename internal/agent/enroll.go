package agent

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/pki"
	"github.com/gitter-hub-blip/lightpn/internal/proto"
	"github.com/oklog/ulid/v2"
)

// Enroll performs the one-time §5.2 flow: generate an identity key pair
// locally, send the CSR with the one-time token, persist the issued
// certificate. The identity private key never leaves this machine.
func Enroll(hubAddr, token, dataDir string) (*Identity, error) {
	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := pki.NewIdentityKey(hostname)
	if err != nil {
		return nil, err
	}

	// Server-auth-only TLS: the CA is unknown until enroll_ack (TOFU), so
	// the first connection cannot verify the chain.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second}, "tcp", hubAddr,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	)
	if err != nil {
		return nil, fmt.Errorf("connect hub: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	env, err := proto.NewEnvelope(proto.TypeEnroll, ulid.Make().String(), proto.EnrollData{
		Token:    token,
		Hostname: hostname,
		CSRPEM:   csrPEM,
	})
	if err != nil {
		return nil, err
	}
	if err := proto.WriteFrame(conn, env); err != nil {
		return nil, err
	}
	resp, err := proto.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("read enroll response: %w", err)
	}
	if resp.Type == proto.TypeError {
		var e proto.ErrorData
		json.Unmarshal(resp.Data, &e)
		return nil, fmt.Errorf("enrollment rejected: %s (%s)", e.Msg, e.Code)
	}
	if resp.Type != proto.TypeEnrollAck {
		return nil, fmt.Errorf("unexpected response type %q", resp.Type)
	}
	var ack proto.EnrollAckData
	if err := json.Unmarshal(resp.Data, &ack); err != nil {
		return nil, err
	}
	fp, err := CAFingerprintOf(ack.CAPEM)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		Dir:           dataDir,
		NodeID:        ack.NodeID,
		ControlAddr:   ack.ControlAddr,
		OverlayIP:     ack.OverlayIP,
		OverlayCIDR:   ack.OverlayCIDR,
		CAFingerprint: fp,
	}
	if err := id.Save(keyPEM, ack.CertPEM, ack.CAPEM); err != nil {
		return nil, fmt.Errorf("persist identity: %w", err)
	}
	return id, nil
}
