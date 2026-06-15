package shared

import "time"

const DefaultRequestTimeoutSeconds = 3

const DefaultRequestTimeout = time.Duration(DefaultRequestTimeoutSeconds) * time.Second

func NormalizeRequestTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return DefaultRequestTimeout
}
