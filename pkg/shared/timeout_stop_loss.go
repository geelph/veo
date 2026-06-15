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
	total               int
	timeouts            int
	consecutiveTimeouts int
	minSamples          int
	maxConsecutive      int
	timeoutRate         int
}

func NewTimeoutStopLoss() *TimeoutStopLoss {
	return &TimeoutStopLoss{
		minSamples:     10,
		maxConsecutive: 5,
		timeoutRate:    90,
	}
}

func (s *TimeoutStopLoss) Record(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.total++
	if !IsTimeoutOrCanceledError(err) {
		s.consecutiveTimeouts = 0
		return false
	}

	s.timeouts++
	s.consecutiveTimeouts++
	if s.consecutiveTimeouts >= s.maxConsecutive {
		return true
	}
	return s.total >= s.minSamples && s.timeouts*100/s.total >= s.timeoutRate
}
