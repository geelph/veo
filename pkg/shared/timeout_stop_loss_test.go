package shared

import (
	"context"
	"testing"
)

func TestTimeoutStopLossTripsOnConsecutiveTimeouts(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()
	err := context.DeadlineExceeded

	for i := 0; i < 4; i++ {
		if stopLoss.Record(err) {
			t.Fatalf("stop loss tripped too early at %d", i+1)
		}
	}
	if !stopLoss.Record(err) {
		t.Fatal("expected stop loss to trip after consecutive timeouts")
	}
}

func TestTimeoutStopLossResetsConsecutiveTimeoutsOnSuccess(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()
	err := context.DeadlineExceeded

	for i := 0; i < 4; i++ {
		stopLoss.Record(err)
	}
	if stopLoss.Record(nil) {
		t.Fatal("success should not trip stop loss")
	}
	if stopLoss.Record(err) {
		t.Fatal("success should reset consecutive timeout count")
	}
}
