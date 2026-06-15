package cli

import (
	"strings"
	"time"

	"veo/internal/config"
	requests "veo/pkg/processor"
	"veo/pkg/shared"
)

type RuntimeConfig struct {
	Request *requests.RequestConfig
	Headers map[string]string
	Proxy   string
}

func buildRuntimeConfig(args *CLIArgs) *RuntimeConfig {
	headers := config.GetCustomHeaders()
	proxyURL := effectiveProxyURL(args)

	return &RuntimeConfig{
		Request: buildActiveRequestConfig(args, proxyURL),
		Headers: headers,
		Proxy:   proxyURL,
	}
}

func buildActiveRequestConfig(args *CLIArgs, proxyURL string) *requests.RequestConfig {
	threads := 100
	retry := 1
	timeout := shared.DefaultRequestTimeout
	randomUA := false

	if args != nil {
		if args.Threads > 0 {
			threads = args.Threads
		}
		if args.RetrySet {
			retry = args.Retry
		}
		if args.Timeout > 0 {
			timeout = time.Duration(args.Timeout) * time.Second
		}
		randomUA = args.RandomUA
	}

	requestConfig := &requests.RequestConfig{
		Timeout:            timeout,
		MaxRetries:         retry,
		MaxConcurrent:      threads,
		RandomUserAgent:    randomUA,
		ProxyURL:           strings.TrimSpace(proxyURL),
		DecompressResponse: true,
	}
	requests.ApplyRedirectPolicy(requestConfig)
	return requestConfig
}

func buildPassiveFingerprintRequestConfig(args *CLIArgs) *requests.RequestConfig {
	procConfig := requests.GetDefaultConfig()

	if globalReqConfig := config.GetRequestConfig(); globalReqConfig != nil {
		if globalReqConfig.Timeout > 0 {
			procConfig.Timeout = time.Duration(globalReqConfig.Timeout) * time.Second
		}
		if globalReqConfig.Retry > 0 {
			procConfig.MaxRetries = globalReqConfig.Retry
		}
		if globalReqConfig.Threads > 0 {
			procConfig.MaxConcurrent = globalReqConfig.Threads
		}
		if globalReqConfig.RandomUA != nil {
			procConfig.RandomUserAgent = *globalReqConfig.RandomUA
		}
	}

	if proxyURL := effectiveProxyURL(args); proxyURL != "" {
		procConfig.ProxyURL = proxyURL
	}
	return procConfig
}

func effectiveProxyURL(args *CLIArgs) string {
	if args != nil {
		if proxyURL := strings.TrimSpace(args.Proxy); proxyURL != "" {
			return proxyURL
		}
	}
	if proxyCfg := config.GetProxyConfig(); proxyCfg != nil {
		return strings.TrimSpace(proxyCfg.UpstreamProxy)
	}
	return ""
}
