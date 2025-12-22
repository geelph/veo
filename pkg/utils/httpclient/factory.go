package httpclient

import (
	"crypto/tls"
)

// ClientFactory HTTP客户端工厂 (兼容性保留)
type ClientFactory struct {
	defaultTLSConfig *tls.Config
}

// NewClientFactory 创建HTTP客户端工厂
func NewClientFactory() *ClientFactory {
	return &ClientFactory{
		defaultTLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}
}

// CreateStandardClient 创建标准HTTP客户端
// 注意：现在统一底层使用 fasthttp，该名称仅为兼容性保留
func (f *ClientFactory) CreateStandardClient(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	return New(config)
}

// CreateClientWithUserAgent 创建带自定义UserAgent的客户端
func (f *ClientFactory) CreateClientWithUserAgent(userAgent string) *Client {
	config := DefaultConfigWithUserAgent(userAgent)
	return f.CreateStandardClient(config)
}

// GetDefaultTLSConfig 获取默认TLS配置
func (f *ClientFactory) GetDefaultTLSConfig() *tls.Config {
	return f.defaultTLSConfig.Clone()
}

// 全局工厂实例
var globalFactory = NewClientFactory()

// GetGlobalFactory 获取全局HTTP客户端工厂实例
func GetGlobalFactory() *ClientFactory {
	return globalFactory
}

// CreateClient 便捷函数
func CreateClient(config *Config) *Client {
	return globalFactory.CreateStandardClient(config)
}

// CreateClientWithUserAgent 便捷函数
func CreateClientWithUserAgent(userAgent string) *Client {
	return globalFactory.CreateClientWithUserAgent(userAgent)
}
