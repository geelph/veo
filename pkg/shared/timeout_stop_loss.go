package shared

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
)

const (
	DefaultTimeoutStopLossMaxConsecutiveTimeouts = 500
	DefaultTimeoutStopLossMinSamples             = 1000
	DefaultTimeoutStopLossTimeoutRatio           = 0.9
)

type TimeoutErrorClass int

const (
	ErrorClassOther TimeoutErrorClass = iota
	ErrorClassTimeout
	ErrorClassCanceled
)

type TimeoutStopLossConfig struct {
	MaxConsecutiveTimeouts int
	MinSamples             int
	TimeoutRatio           float64
}

type TimeoutStopLoss struct {
	mu                  sync.Mutex
	consecutiveTimeouts int
	timeoutSamples      int
	totalSamples        int
	config              TimeoutStopLossConfig
}

func NewTimeoutStopLoss() *TimeoutStopLoss {
	return NewTimeoutStopLossWithConfig(TimeoutStopLossConfig{})
}

func NewTimeoutStopLossWithConfig(config TimeoutStopLossConfig) *TimeoutStopLoss {
	return &TimeoutStopLoss{config: normalizeTimeoutStopLossConfig(config)}
}

func ClassifyTimeoutError(err error) TimeoutErrorClass {
	if err == nil {
		return ErrorClassOther
	}
	if errors.Is(err, context.Canceled) {
		return ErrorClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorClassTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrorClassTimeout
	}

	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "context canceled") ||
		strings.Contains(errText, "context cancelled") ||
		strings.Contains(errText, "operation was canceled") ||
		strings.Contains(errText, "operation was cancelled") {
		return ErrorClassCanceled
	}
	if strings.Contains(errText, "timeout") ||
		strings.Contains(errText, "timed out") ||
		strings.Contains(errText, "deadline exceeded") ||
		strings.Contains(errText, "i/o timeout") {
		return ErrorClassTimeout
	}
	return ErrorClassOther
}

func IsTimeoutError(err error) bool {
	return ClassifyTimeoutError(err) == ErrorClassTimeout
}

func IsCanceledError(err error) bool {
	return ClassifyTimeoutError(err) == ErrorClassCanceled
}

func IsTimeoutOrCanceledError(err error) bool {
	class := ClassifyTimeoutError(err)
	return class == ErrorClassTimeout || class == ErrorClassCanceled
}

func (s *TimeoutStopLoss) Record(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	class := ClassifyTimeoutError(err)
	if class == ErrorClassCanceled {
		return false
	}

	s.totalSamples++
	if class == ErrorClassTimeout {
		s.timeoutSamples++
		s.consecutiveTimeouts++
	} else {
		s.consecutiveTimeouts = 0
	}

	return s.consecutiveTimeouts >= s.config.MaxConsecutiveTimeouts ||
		(s.totalSamples >= s.config.MinSamples && float64(s.timeoutSamples) >= float64(s.totalSamples)*s.config.TimeoutRatio)
}

func normalizeTimeoutStopLossConfig(config TimeoutStopLossConfig) TimeoutStopLossConfig {
	if config.MaxConsecutiveTimeouts <= 0 {
		config.MaxConsecutiveTimeouts = DefaultTimeoutStopLossMaxConsecutiveTimeouts
	}
	if config.MinSamples <= 0 {
		config.MinSamples = DefaultTimeoutStopLossMinSamples
	}
	if config.TimeoutRatio <= 0 || config.TimeoutRatio > 1 {
		config.TimeoutRatio = DefaultTimeoutStopLossTimeoutRatio
	}
	return config
}
