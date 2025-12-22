package fingerprint

import (
	"fmt"
	"net/url"

	"veo/pkg/utils/httpclient"
)

// createDSLContext 创建DSL解析上下文（基础版本，用于被动识别）
func (e *Engine) createDSLContext(response *HTTPResponse) *DSLContext {
	return e.createDSLContextWithClient(response, nil, "")
}

// createDSLContextWithClient 创建DSL解析上下文（增强版，支持主动探测）
func (e *Engine) createDSLContextWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) *DSLContext {
	headers := make(map[string][]string)
	if response != nil && len(response.ResponseHeaders) > 0 {
		headers = make(map[string][]string, len(response.ResponseHeaders))
		for name, values := range response.ResponseHeaders {
			if len(values) == 0 {
				continue
			}
			dup := make([]string, len(values))
			copy(dup, values)
			headers[name] = dup
		}
	}

	if baseURL == "" && response != nil && response.URL != "" {
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
	}

	var body, urlStr, method string
	if response != nil {
		body = response.Body
		urlStr = response.URL
		method = response.Method
	}

	return &DSLContext{
		Response:   response,
		Headers:    headers,
		Body:       body,
		URL:        urlStr,
		Method:     method,
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		Engine:     e,
	}
}
