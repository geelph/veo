package shared

import (
	"context"
	"fmt"
	"testing"
)

func TestTimeoutStopLossTripsOnConsecutiveTimeouts(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()
	err := context.DeadlineExceeded

	for i := 0; i < DefaultTimeoutStopLossMaxConsecutiveTimeouts-1; i++ {
		if stopLoss.Record(err) {
			t.Fatalf("stop loss tripped too early at %d", i+1)
		}
	}
	if !stopLoss.Record(err) {
		t.Fatal("expected stop loss to trip after consecutive timeouts")
	}
}

func TestTimeoutStopLossResetsConsecutiveTimeoutsOnSuccess(t *testing.T) {
	stopLoss := NewTimeoutStopLossWithConfig(TimeoutStopLossConfig{
		MaxConsecutiveTimeouts: 5,
		MinSamples:             DefaultTimeoutStopLossMinSamples,
		TimeoutRatio:           DefaultTimeoutStopLossTimeoutRatio,
	})
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

func TestTimeoutStopLossDoesNotTripOnIntermittentSuccess(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()
	err := context.DeadlineExceeded

	for i := 0; i < 1000; i++ {
		if stopLoss.Record(err) {
			t.Fatalf("intermittent timeout tripped stop loss at request %d", i*2+1)
		}
		if stopLoss.Record(nil) {
			t.Fatalf("success tripped stop loss at request %d", i*2+2)
		}
	}
}

func TestTimeoutStopLossRequiresMinimumSamplesForTimeoutRatio(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()
	samples := 0

	for batch := 0; batch < 99; batch++ {
		for i := 0; i < 9; i++ {
			samples++
			if stopLoss.Record(context.DeadlineExceeded) {
				t.Fatalf("stop loss tripped before minimum samples at sample %d", samples)
			}
		}
		samples++
		if stopLoss.Record(fmt.Errorf("connection refused")) {
			t.Fatalf("stop loss tripped before minimum samples at sample %d", samples)
		}
	}

	for i := 0; i < 9; i++ {
		samples++
		if stopLoss.Record(context.DeadlineExceeded) {
			t.Fatalf("stop loss tripped before minimum samples at sample %d", samples)
		}
	}
	if samples != DefaultTimeoutStopLossMinSamples-1 {
		t.Fatalf("samples = %d, want %d", samples, DefaultTimeoutStopLossMinSamples-1)
	}
}

func TestTimeoutStopLossTripsOnHighTimeoutRatio(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()

	for batch := 0; batch < 100; batch++ {
		for i := 0; i < 9; i++ {
			if stopLoss.Record(context.DeadlineExceeded) {
				t.Fatalf("ratio stop loss tripped before 1000 samples at batch %d timeout %d", batch+1, i+1)
			}
		}

		tripped := stopLoss.Record(fmt.Errorf("connection refused"))
		if batch < 99 && tripped {
			t.Fatalf("ratio stop loss tripped too early at batch %d", batch+1)
		}
		if batch == 99 && !tripped {
			t.Fatal("expected stop loss to trip when 900 of 1000 samples are timeouts")
		}
	}
}

func TestTimeoutStopLossDoesNotTripBelowTimeoutRatio(t *testing.T) {
	stopLoss := NewTimeoutStopLoss()

	for batch := 0; batch < 100; batch++ {
		timeouts := 9
		if batch == 99 {
			timeouts = 8
		}

		for i := 0; i < timeouts; i++ {
			if stopLoss.Record(context.DeadlineExceeded) {
				t.Fatalf("stop loss tripped below ratio at batch %d timeout %d", batch+1, i+1)
			}
		}

		if stopLoss.Record(fmt.Errorf("connection refused")) {
			t.Fatalf("stop loss tripped below ratio at batch %d non-timeout", batch+1)
		}
	}

	if stopLoss.Record(nil) {
		t.Fatal("stop loss tripped below ratio after 899 of 1000 samples timed out")
	}
}

func TestTimeoutStopLossIgnoresCanceledErrors(t *testing.T) {
	stopLoss := NewTimeoutStopLossWithConfig(TimeoutStopLossConfig{
		MaxConsecutiveTimeouts: 1,
		MinSamples:             1,
		TimeoutRatio:           DefaultTimeoutStopLossTimeoutRatio,
	})

	if stopLoss.Record(context.Canceled) {
		t.Fatal("context.Canceled should not trip stop loss")
	}
	if stopLoss.Record(fmt.Errorf("wrapped: %w", context.Canceled)) {
		t.Fatal("wrapped context.Canceled should not trip stop loss")
	}
	if stopLoss.Record(fmt.Errorf("request failed: context canceled")) {
		t.Fatal("context canceled text should not trip stop loss")
	}
}

func TestClassifyTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want TimeoutErrorClass
	}{
		{name: "nil", err: nil, want: ErrorClassOther},
		{name: "deadline", err: context.DeadlineExceeded, want: ErrorClassTimeout},
		{name: "wrapped deadline", err: fmt.Errorf("request failed: %w", context.DeadlineExceeded), want: ErrorClassTimeout},
		{name: "canceled", err: context.Canceled, want: ErrorClassCanceled},
		{name: "wrapped canceled", err: fmt.Errorf("request failed: %w", context.Canceled), want: ErrorClassCanceled},
		{name: "canceled text", err: fmt.Errorf("request failed: context canceled"), want: ErrorClassCanceled},
		{name: "timeout text", err: fmt.Errorf("read timeout"), want: ErrorClassTimeout},
		{name: "other", err: fmt.Errorf("connection refused"), want: ErrorClassOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyTimeoutError(tt.err); got != tt.want {
				t.Fatalf("ClassifyTimeoutError() = %v, want %v", got, tt.want)
			}
		})
	}
}
