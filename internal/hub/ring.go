package hub

import (
	"sync"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// ringSlots: 24h at 30s granularity.
const (
	ringStep  = 30 // seconds per slot
	ringSlots = 24 * 3600 / ringStep
)

// Sample is one downsampled metrics point.
type Sample struct {
	TS       int64   `json:"ts"`
	CPUPct   float64 `json:"cpu"`
	MemPct   float64 `json:"mem"`
	DiskPct  float64 `json:"disk"`
	RxRate   float64 `json:"rx_rate"` // bytes/s
	TxRate   float64 `json:"tx_rate"`
	Load1    float64 `json:"load1"`
	MemUsed  uint64  `json:"mem_used"`
	MemTotal uint64  `json:"mem_total"`
}

// nodeRing holds one node's history plus the previous raw counters for
// rate differentiation.
type nodeRing struct {
	slots  [ringSlots]Sample
	lastTS int64 // ts of most recent heartbeat ingested
	prevRx uint64
	prevTx uint64
	prevTS int64
}

// Metrics is the in-memory metrics store for all nodes. Nothing here is
// persisted (design invariant 4).
type Metrics struct {
	mu    sync.RWMutex
	rings map[string]*nodeRing
}

func NewMetrics() *Metrics {
	return &Metrics{rings: map[string]*nodeRing{}}
}

// Ingest records a heartbeat's system metrics for node id.
func (m *Metrics) Ingest(id string, ts int64, sys proto.SysMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rings[id]
	if r == nil {
		r = &nodeRing{}
		m.rings[id] = r
	}
	s := Sample{
		TS:       ts - ts%ringStep,
		CPUPct:   sys.CPUPct,
		Load1:    sys.Load1,
		MemUsed:  sys.MemUsed,
		MemTotal: sys.MemTotal,
	}
	if sys.MemTotal > 0 {
		s.MemPct = float64(sys.MemUsed) / float64(sys.MemTotal) * 100
	}
	if sys.DiskTotal > 0 {
		s.DiskPct = float64(sys.DiskUsed) / float64(sys.DiskTotal) * 100
	}
	// Differentiate cumulative counters into rates; counter reset (reboot)
	// yields a skipped point, not a negative spike.
	if r.prevTS > 0 && ts > r.prevTS && sys.NetRx >= r.prevRx && sys.NetTx >= r.prevTx {
		dt := float64(ts - r.prevTS)
		s.RxRate = float64(sys.NetRx-r.prevRx) / dt
		s.TxRate = float64(sys.NetTx-r.prevTx) / dt
	}
	r.prevRx, r.prevTx, r.prevTS = sys.NetRx, sys.NetTx, ts
	r.lastTS = ts
	r.slots[(ts/ringStep)%ringSlots] = s
}

// Range returns samples for node id in [from, to], oldest first.
func (m *Metrics) Range(id string, from, to int64) []Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := m.rings[id]
	if r == nil {
		return nil
	}
	var out []Sample
	for i := 0; i < ringSlots; i++ {
		s := r.slots[i]
		if s.TS >= from && s.TS <= to {
			out = append(out, s)
		}
	}
	// Slots are indexed by (ts/step)%slots so iteration order is not
	// chronological; sort by TS (insertion order within a day is fine).
	sortSamples(out)
	return out
}

// Latest returns the most recent sample for node id, if any.
func (m *Metrics) Latest(id string) (Sample, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := m.rings[id]
	if r == nil || r.lastTS == 0 {
		return Sample{}, false
	}
	return r.slots[(r.lastTS/ringStep)%ringSlots], true
}

// Drop discards a node's history (on node deletion).
func (m *Metrics) Drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rings, id)
}

func sortSamples(s []Sample) {
	// insertion sort: slices are near-sorted already
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].TS > s[j].TS; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
