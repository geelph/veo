package shared

import (
	"regexp"
	"sync"
)

var timeoutErrorRegex = regexp.MustCompile(`(?i)(timeout|timed out|context canceled|context deadline exceeded|dial timeout|read timeout|write timeout|i/o timeout|deadline exceeded|operation was canceled)`)

func IsTimeoutOrCanceledError(err error) bool {
	if err == nil {
		return false
	}
	return timeoutErrorRegex.MatchString(err.Error())
}

type TimeoutStopLoss struct {
	mu                  sync.Mutex
	consecutiveTimeouts int
	maxConsecutive      int
}

func NewTimeoutStopLoss() *TimeoutStopLoss {
	return &TimeoutStopLoss{
		maxConsecutive: 5,
	}
}

func (s *TimeoutStopLoss) Record(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !IsTimeoutOrCanceledError(err) {
		s.consecutiveTimeouts = 0
		return false
	}

	s.consecutiveTimeouts++
	return s.consecutiveTimeouts >= s.maxConsecutive
}
