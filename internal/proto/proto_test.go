package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	env, err := NewEnvelope(TypeHeartbeat, "01TEST", HeartbeatData{
		TS:  123,
		Sys: SysMetrics{CPUPct: 42.5, MemUsed: 100, MemTotal: 200},
		WG:  []WGPeerStatus{{PeerNodeID: "01PEER", RxBytes: 7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, env); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != Version || got.Type != TypeHeartbeat || got.ID != "01TEST" {
		t.Fatalf("envelope mismatch: %+v", got)
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	buf.Write(hdr[:])
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("expected error for oversize frame")
	}
}

func TestFrameRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("expected error for zero-length frame")
	}
}
