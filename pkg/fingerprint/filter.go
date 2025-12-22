package fingerprint

import (
	"strings"

	"veo/pkg/utils/logger"
)

// shouldFilterResponse 检查是否应该过滤响应
func (e *Engine) shouldFilterResponse(response *HTTPResponse) bool {
	// 检查响应体大小
	if e.config.MaxBodySize > 0 && len(response.Body) > e.config.MaxBodySize {
		logger.Debugf("过滤大响应体: %s (大小: %d bytes, 限制: %d bytes)",
			response.URL, len(response.Body), e.config.MaxBodySize)
		return true
	}

	// 检查是否为静态文件（基于URL路径）
	if e.isStaticFile(response.URL) {
		logger.Debugf("过滤静态文件: %s", response.URL)
		return true
	}

	// 检查Content-Type
	if e.isStaticContentType(response.ContentType) {
		logger.Debugf("过滤静态内容类型: %s (Content-Type: %s)",
			response.URL, response.ContentType)
		return true
	}

	return false
}

// isStaticFile 检查URL是否指向静态文件
func (e *Engine) isStaticFile(rawURL string) bool {
	if !e.config.StaticFileFilterEnabled || len(e.config.StaticExtensions) == 0 {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	for _, ext := range e.config.StaticExtensions {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lowerURL, strings.ToLower(ext)) {
			return true
		}
	}

	return false
}

// isStaticContentType 检查Content-Type是否为静态类型
func (e *Engine) isStaticContentType(contentType string) bool {
	if !e.config.ContentTypeFilterEnabled || len(e.config.StaticContentTypes) == 0 {
		return false
	}

	contentType = strings.ToLower(contentType)

	for _, staticType := range e.config.StaticContentTypes {
		if staticType == "" {
			continue
		}
		if strings.HasPrefix(contentType, strings.ToLower(staticType)) {
			return true
		}
	}

	return false
}
