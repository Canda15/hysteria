package brutal

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// feedAckRate drives a single sampling slot with the given number of acked and
// lost packets and returns the resulting ackRate.
func feedAckRate(disableLossCompensation bool, ackCount, lossCount int) float64 {
	b := NewBrutalSender(1000000, disableLossCompensation)
	acked := make([]congestion.AckedPacketInfo, ackCount)
	lost := make([]congestion.LostPacketInfo, lossCount)
	// eventTime lands in a fixed slot; a single event carries enough samples.
	b.OnCongestionEventEx(0, monotime.Time(5*time.Second), acked, lost)
	return b.ackRate
}

func TestBrutalLossCompensation(t *testing.T) {
	tests := []struct {
		name      string
		ack, loss int
		want      float64 // expected ackRate when compensation is ENABLED
	}{
		{"no loss", 100, 0, 1.0},
		{"20% loss", 80, 20, 0.8},
		{"50% loss clamps to floor", 50, 50, minAckRate}, // 0.5 clamped up to 0.8
		{"few samples stays 1", 10, 5, 1.0},              // below minSampleCount
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compensation enabled (default behavior): ackRate reacts to loss.
			if got := feedAckRate(false, tt.ack, tt.loss); got != tt.want {
				t.Errorf("compensation on: ackRate = %v, want %v", got, tt.want)
			}
			// Compensation disabled: ackRate must stay pinned at 1 regardless.
			if got := feedAckRate(true, tt.ack, tt.loss); got != 1.0 {
				t.Errorf("compensation off: ackRate = %v, want 1.0", got)
			}
		})
	}
}

func TestBrutalSpuriousLossCorrection(t *testing.T) {
	b := NewBrutalSender(1000000, false)
	acked := make([]congestion.AckedPacketInfo, 80)
	lost := make([]congestion.LostPacketInfo, 50)
	b.OnCongestionEventEx(0, monotime.Time(5*time.Second), acked, lost)
	if b.ackRate != minAckRate {
		t.Fatalf("ackRate = %v, want %v (clamped)", b.ackRate, minAckRate)
	}

	// 40 of the losses turn out to be spurious: retracting them lifts the ack
	// rate back above the clamp threshold (80 acked / 10 real losses).
	b.OnSpuriousLoss(40)
	b.updateAckRate(5)
	if want := 80.0 / 90.0; b.ackRate != want {
		t.Errorf("ackRate = %v, want %v", b.ackRate, want)
	}
	if b.spuriousCredit != 0 {
		t.Errorf("spuriousCredit = %d, want 0 (fully consumed)", b.spuriousCredit)
	}

	// Credit that exceeds the losses currently in the window is kept for
	// future retraction instead of being dropped.
	b.OnSpuriousLoss(60)
	b.updateAckRate(5)
	if b.ackRate != 1.0 {
		t.Errorf("ackRate = %v, want 1.0 (no real losses left)", b.ackRate)
	}
	if b.spuriousCredit != 10 {
		t.Errorf("spuriousCredit = %d, want 10", b.spuriousCredit)
	}

	// With loss compensation disabled, spurious losses are not tracked at all.
	b2 := NewBrutalSender(1000000, true)
	b2.OnSpuriousLoss(40)
	if b2.spuriousCredit != 0 {
		t.Errorf("spuriousCredit = %d, want 0 (compensation disabled)", b2.spuriousCredit)
	}
}
