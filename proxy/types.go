//go:build passive

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"veo/internal/config"
	"veo/pkg/logger"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/atomic"
	"golang.org/x/net/http2"
	xproxy "golang.org/x/net/proxy"
)

type Options struct {
	Addr              string
	StreamLargeBodies int64
	SslInsecure       bool
	Upstream          string
}

type Proxy struct {
	Opts   *Options
	Addons []Addon

	entry    *entry
	attacker *attacker
}

var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5
	}

	proxy := &Proxy{
		Opts:   opts,
		Addons: make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) onClientConnected(client *ClientConn) {
	for _, addon := range proxy.Addons {
		addon.ClientConnected(client)
	}
}

func (proxy *Proxy) onClientDisconnected(client *ClientConn) {
	for _, addon := range proxy.Addons {
		addon.ClientDisconnected(client)
	}
}

func (proxy *Proxy) onServerConnected(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.ServerConnected(connCtx)
	}
}

func (proxy *Proxy) onServerDisconnected(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.ServerDisconnected(connCtx)
	}
}

func (proxy *Proxy) onTLSEstablishedServer(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.TlsEstablishedServer(connCtx)
	}
}

func (proxy *Proxy) onRequestheaders(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Requestheaders(flow)
	}
}

func (proxy *Proxy) onRequestheadersUntilResponse(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Requestheaders(flow)
		if flow.Response != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onRequestUntilResponse(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Request(flow)
		if flow.Response != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onResponseheaders(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Responseheaders(flow)
	}
}

func (proxy *Proxy) onResponseheadersUntilBody(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Responseheaders(flow)
		if flow.Response != nil && flow.Response.Body != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onResponse(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Response(flow)
	}
}

func (proxy *Proxy) onStreamRequestModifier(flow *Flow, in io.Reader) io.Reader {
	out := in
	for _, addon := range proxy.Addons {
		out = addon.StreamRequestModifier(flow, out)
	}
	return out
}

func (proxy *Proxy) onStreamResponseModifier(flow *Flow, in io.Reader) io.Reader {
	out := in
	for _, addon := range proxy.Addons {
		out = addon.StreamResponseModifier(flow, out)
	}
	return out
}

func newNoRedirectClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			logger.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyURL(req)
	}
}

func (proxy *Proxy) getUpstreamProxyURL(req *http.Request) (*url.URL, error) {
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyURL, err := proxy.getUpstreamProxyURL(req)
	if err != nil {
		return nil, err
	}

	address := CanonicalAddr(req.URL)
	if proxyURL != nil {
		return GetProxyConn(ctx, proxyURL, address, proxy.Opts.SslInsecure)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

type Addon interface {
	ClientConnected(*ClientConn)
	ClientDisconnected(*ClientConn)
	ServerConnected(*ConnContext)
	ServerDisconnected(*ConnContext)
	TlsEstablishedServer(*ConnContext)
	Requestheaders(*Flow)
	Request(*Flow)
	Responseheaders(*Flow)
	Response(*Flow)
	StreamRequestModifier(*Flow, io.Reader) io.Reader
	StreamResponseModifier(*Flow, io.Reader) io.Reader
}

type BaseAddon struct{}

func (addon *BaseAddon) ClientConnected(*ClientConn)                            {}
func (addon *BaseAddon) ClientDisconnected(*ClientConn)                         {}
func (addon *BaseAddon) ServerConnected(*ConnContext)                           {}
func (addon *BaseAddon) ServerDisconnected(*ConnContext)                        {}
func (addon *BaseAddon) TlsEstablishedServer(*ConnContext)                      {}
func (addon *BaseAddon) Requestheaders(*Flow)                                   {}
func (addon *BaseAddon) Request(*Flow)                                          {}
func (addon *BaseAddon) Responseheaders(*Flow)                                  {}
func (addon *BaseAddon) Response(*Flow)                                         {}
func (addon *BaseAddon) StreamRequestModifier(f *Flow, in io.Reader) io.Reader  { return in }
func (addon *BaseAddon) StreamResponseModifier(f *Flow, in io.Reader) io.Reader { return in }

type ClientConn struct {
	Id                 uuid.UUID
	Conn               net.Conn
	Tls                bool
	NegotiatedProtocol string
	UpstreamCert       bool
	clientHello        *tls.ClientHelloInfo
}

func newClientConn(c net.Conn) *ClientConn {
	return &ClientConn{
		Id:           uuid.NewV4(),
		Conn:         c,
		Tls:          false,
		UpstreamCert: true,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["tls"] = c.Tls
	m["address"] = c.Conn.RemoteAddr().String()
	return json.Marshal(m)
}

type ServerConn struct {
	Id      uuid.UUID
	Address string
	Conn    net.Conn

	client   *http.Client
	tlsConn  *tls.Conn
	tlsState *tls.ConnectionState
}

func newServerConn() *ServerConn {
	return &ServerConn{
		Id: uuid.NewV4(),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["address"] = c.Address
	peername := ""
	if c.Conn != nil {
		peername = c.Conn.RemoteAddr().String()
	}
	m["peername"] = peername
	return json.Marshal(m)
}

func (c *ServerConn) TlsState() *tls.ConnectionState {
	return c.tlsState
}

var connContextKey = new(struct{})

type ConnContext struct {
	ClientConn *ClientConn   `json:"clientConn"`
	ServerConn *ServerConn   `json:"serverConn"`
	Intercept  bool          `json:"intercept"`
	FlowCount  atomic.Uint32 `json:"-"`

	proxy              *Proxy
	closeAfterResponse bool
	dialFn             func(context.Context) error
}

func newConnContext(c net.Conn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (connCtx *ConnContext) Id() uuid.UUID {
	return connCtx.ClientConn.Id
}

type Request struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte

	raw *http.Request
}

func newRequest(req *http.Request) *Request {
	return &Request{
		Method: req.Method,
		URL:    req.URL,
		Proto:  req.Proto,
		Header: req.Header,
		raw:    req,
	}
}

func (r *Request) Raw() *http.Request {
	return r.raw
}

func (req *Request) MarshalJSON() ([]byte, error) {
	r := make(map[string]interface{})
	r["method"] = req.Method
	r["url"] = req.URL.String()
	r["proto"] = req.Proto
	r["header"] = req.Header
	return json.Marshal(r)
}

func (req *Request) UnmarshalJSON(data []byte) error {
	r := make(map[string]interface{})
	err := json.Unmarshal(data, &r)
	if err != nil {
		return err
	}

	rawurl, ok := r["url"].(string)
	if !ok {
		return errors.New("url parse error")
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}

	rawheader, ok := r["header"].(map[string]interface{})
	if !ok {
		return errors.New("rawheader parse error")
	}

	header := make(map[string][]string)
	for k, v := range rawheader {
		vals, ok := v.([]interface{})
		if !ok {
			return errors.New("header parse error")
		}

		svals := make([]string, 0)
		for _, val := range vals {
			sval, ok := val.(string)
			if !ok {
				return errors.New("header parse error")
			}
			svals = append(svals, sval)
		}
		header[k] = svals
	}

	*req = Request{
		Method: r["method"].(string),
		URL:    u,
		Proto:  r["proto"].(string),
		Header: header,
	}
	return nil
}

type Response struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"-"`
	BodyReader io.Reader

	close bool
}

type Flow struct {
	Id          uuid.UUID
	ConnContext *ConnContext
	Request     *Request
	Response    *Response

	Stream            bool
	UseSeparateClient bool
	done              chan struct{}
}

func newFlow() *Flow {
	return &Flow{
		Id:   uuid.NewV4(),
		done: make(chan struct{}),
	}
}

func (f *Flow) Done() <-chan struct{} {
	return f.done
}

func (f *Flow) finish() {
	close(f.done)
}

func (f *Flow) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{})
	j["id"] = f.Id
	j["request"] = f.Request
	j["response"] = f.Response
	return json.Marshal(j)
}

var normalErrSubstrings = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
	"http2: stream closed",
	"http2: server",
	"http2: stream reset",
	"context canceled",
	"operation was canceled",
}

func logErr(prefix string, err error) {
	if err == nil {
		return
	}
	msg := err.Error()

	for _, str := range normalErrSubstrings {
		if strings.Contains(msg, str) {
			logger.Debugf("%s %v", prefix, err)
			return
		}
	}

	logger.Errorf("%s %v", prefix, err)
}

// 转发流量
func transfer(prefix string, server, client io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(server, client)
		logger.Debugf("%s client copy end %v", prefix, err)
		client.Close()
		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()
	go func() {
		_, err := io.Copy(client, server)
		logger.Debugf("%s server copy end %v", prefix, err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			if tcpConn, ok := clientConn.Conn.(*net.TCPConn); ok {
				err := tcpConn.CloseRead()
				logger.Debugf("%s clientConn.Conn.(*net.TCPConn).CloseRead() %v", prefix, err)
			}
		}

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logErr(prefix, err)
			return
		}
	}
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`) // Indicates that the proxy server requires client credentials
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	if int64(buf.Len()) == limit {
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	return buf.Bytes(), nil, nil
}

func CanonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = getDefaultPort(url.Scheme)
	}
	return net.JoinHostPort(url.Hostname(), port)
}

func getDefaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5":
		return "1080"
	default:
		return ""
	}
}

func GetProxyConn(ctx context.Context, proxyURL *url.URL, address string, sslInsecure bool) (net.Conn, error) {
	if proxyURL.Scheme == "socks5" {
		proxyAuth := &xproxy.Auth{}
		if proxyURL.User != nil {
			user := proxyURL.User.Username()
			pass, _ := proxyURL.User.Password()
			proxyAuth.User = user
			proxyAuth.Password = pass
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, proxyAuth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		conn, err := dc.DialContext(ctx, "tcp", address)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
		return conn, nil
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}

	if proxyURL.Scheme == "https" {
		tlsConfig := &tls.Config{
			ServerName:         proxyURL.Hostname(),
			InsecureSkipVerify: sslInsecure,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: http.Header{},
	}
	if proxyURL.User != nil {
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String())))
	}

	connectCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	didReadResponse := make(chan struct{})
	var resp *http.Response

	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()

	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
	}

	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_, text, ok := strings.Cut(resp.Status, " ")
		conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}

	return conn, nil
}
func extractHost(hostWithPort string) string {
	host, _, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		// 如果没有端口或格式不正确，直接返回原始字符串
		return hostWithPort
	}
	return host
}

func isTLS(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	return buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03
}

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	proxy.onClientConnected(connCtx.ClientConn)

	return wc, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	// log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	c.proxy.onClientDisconnected(c.connCtx.ClientConn)

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	// log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	c.proxy.onServerDisconnected(c.connCtx)

	if !c.connCtx.ClientConn.Tls {
		if clientConn, ok := c.connCtx.ClientConn.Conn.(*wrapClientConn); ok {
			if tcpConn, ok := clientConn.Conn.(*net.TCPConn); ok {
				tcpConn.CloseRead()
			}
		}
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	logger.Infof("Listend at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.ServeHTTP host=%s]", req.Host)

	// 检查主机是否被允许（对于有效的代理请求）
	if req.URL.IsAbs() && req.URL.Host != "" {
		host := extractHost(req.URL.Host) // 🔧 提取主机名（去除端口）
		if !config.IsHostAllowed(host) {
			logger.Debugf("%s 主机被拒绝，拒绝代理: %s (原始: %s)", prefix, host, req.URL.Host)
			httpError(res, "Host not allowed", http.StatusForbidden)
			return
		}
	}

	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}
	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.handleConnect host=%s]", req.Host)

	// 检查主机是否被允许
	host := extractHost(req.Host) // 🔧 提取主机名（去除端口）
	if !config.IsHostAllowed(host) {
		logger.Debugf("%s 主机被拒绝，拒绝CONNECT: %s (原始: %s)", prefix, host, req.Host)
		httpError(res, "Host not allowed", http.StatusForbidden)
		return
	}

	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = true
	defer f.finish()

	// trigger addon event Requestheaders
	proxy.onRequestheaders(f)

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	// log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	e.proxy.onResponseheaders(f)

	return cconn, nil
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialFirstAttack host=%s]", req.Host)

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		// log.Error(err)
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		// log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		// log.Error(err)
		return
	}
	if !isTLS(peek) {
		// todo: http, ws
		transfer(prefix, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialLazyAttack host=%s]", req.Host)

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		// log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		// log.Error(err)
		return
	}

	if !isTLS(peek) {
		// todo: http, ws
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			// log.Error(err)
			return
		}
		transfer(prefix, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
}

type attackerListener struct {
	connChan chan net.Conn
}

func (l *attackerListener) accept(conn net.Conn) {
	l.connChan <- conn
}

func (l *attackerListener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}
func (l *attackerListener) Close() error   { return nil }
func (l *attackerListener) Addr() net.Addr { return nil }

type attackerConn struct {
	net.Conn
	connCtx *ConnContext
}

type attacker struct {
	proxy    *Proxy
	ca       cert.CA
	server   *http.Server
	h2Server *http2.Server
	client   *http.Client
	listener *attackerListener
}

func newAttacker(proxy *Proxy) (*attacker, error) {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		return nil, err
	}

	a := &attacker{
		proxy: proxy,
		ca:    ca,
		client: newNoRedirectClient(&http.Transport{
			Proxy:              proxy.realUpstreamProxy(),
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: proxy.Opts.SslInsecure,
				// KeyLogWriter removed - TLS key logging functionality removed
			},
		}),
		listener: &attackerListener{
			connChan: make(chan net.Conn),
		},
	}

	a.server = &http.Server{
		Handler: a,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*attackerConn).connCtx)
		},
	}

	a.h2Server = &http2.Server{
		MaxConcurrentStreams: 100, // todo: wait for remote server setting
		NewWriteScheduler:    func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}

	return a, nil
}

func (a *attacker) start() error {
	return a.server.Serve(a.listener)
}

func (a *attacker) serveConn(clientTlsConn *tls.Conn, connCtx *ConnContext) {
	connCtx.ClientConn.NegotiatedProtocol = clientTlsConn.ConnectionState().NegotiatedProtocol

	if connCtx.ClientConn.NegotiatedProtocol == "h2" && connCtx.ServerConn != nil {
		connCtx.ServerConn.client = newNoRedirectClient(&http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return connCtx.ServerConn.tlsConn, nil
			},
			DisableCompression: true,
		})

		ctx := context.WithValue(context.Background(), connContextKey, connCtx)
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			<-connCtx.ClientConn.Conn.(*wrapClientConn).closeChan
			cancel()
		}()
		go func() {
			a.h2Server.ServeConn(clientTlsConn, &http2.ServeConnOpts{
				Context:    ctx,
				Handler:    a,
				BaseConfig: a.server,
			})
		}()
		return
	}

	a.listener.accept(&attackerConn{
		Conn:    clientTlsConn,
		connCtx: connCtx,
	})
}

func (a *attacker) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	a.attack(res, req)
}

func (a *attacker) initHttpDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)
	connCtx.dialFn = func(ctx context.Context) error {
		addr := CanonicalAddr(req.URL)
		c, err := a.proxy.getUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		proxy := a.proxy
		cw := &wrapServerConn{
			Conn:    c,
			proxy:   proxy,
			connCtx: connCtx,
		}

		serverConn := newServerConn()
		serverConn.Conn = cw
		serverConn.Address = addr
		serverConn.client = newNoRedirectClient(&http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cw, nil
			},
			ForceAttemptHTTP2:  false, // disable http2
			DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
		})

		connCtx.ServerConn = serverConn
		proxy.onServerConnected(connCtx)

		return nil
	}
}

// send clientHello to server, server handshake
func (a *attacker) serverTlsHandshake(ctx context.Context, connCtx *ConnContext) error {
	proxy := a.proxy
	clientHello := connCtx.ClientConn.clientHello
	serverConn := connCtx.ServerConn

	serverTlsConfig := &tls.Config{
		InsecureSkipVerify: proxy.Opts.SslInsecure,
		// KeyLogWriter removed - TLS key logging functionality removed
		ServerName: clientHello.ServerName,
		NextProtos: clientHello.SupportedProtos,
		// CurvePreferences:   clientHello.SupportedCurves, // todo: 如果打开会出错
		CipherSuites: clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		serverTlsConfig.MinVersion = minVersion
		serverTlsConfig.MaxVersion = maxVersion
	}
	serverTlsConn := tls.Client(serverConn.Conn, serverTlsConfig)
	serverConn.tlsConn = serverTlsConn
	if err := serverTlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	serverTlsState := serverTlsConn.ConnectionState()
	serverConn.tlsState = &serverTlsState
	proxy.onTLSEstablishedServer(connCtx)

	serverConn.client = newNoRedirectClient(&http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return serverTlsConn, nil
		},
		ForceAttemptHTTP2:  true,
		DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
	})

	return nil
}

func (a *attacker) initHttpsDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	connCtx.dialFn = func(ctx context.Context) error {
		_, err := a.httpsDial(ctx, req)
		if err != nil {
			return err
		}
		if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
			return err
		}
		return nil
	}
}

func (a *attacker) httpsDial(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxy := a.proxy
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	plainConn, err := proxy.getUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := newServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   proxy,
		connCtx: connCtx,
	}
	connCtx.ServerConn = serverConn
	connCtx.proxy.onServerConnected(connCtx)

	return serverConn.Conn, nil
}

func (a *attacker) httpsTlsDial(ctx context.Context, cconn net.Conn, conn net.Conn) {
	connCtx := cconn.(*wrapClientConn).connCtx
	prefix := fmt.Sprintf("[Proxy.attacker.httpsTlsDial host=%s]", connCtx.ClientConn.Conn.RemoteAddr().String())

	var clientHello *tls.ClientHelloInfo
	clientHelloChan := make(chan *tls.ClientHelloInfo)
	serverTlsStateChan := make(chan *tls.ConnectionState)
	errChan1 := make(chan error, 1)
	errChan2 := make(chan error, 1)
	clientHandshakeDoneChan := make(chan struct{})

	clientTlsConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true, // 设置此值为 true ，确保每次都会调用下面的 GetConfigForClient 方法
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloChan <- chi
			nextProtos := make([]string, 0)

			// wait server handshake finish
			select {
			case err := <-errChan2:
				return nil, err
			case serverTlsState := <-serverTlsStateChan:
				if serverTlsState.NegotiatedProtocol != "" {
					nextProtos = append([]string{serverTlsState.NegotiatedProtocol}, nextProtos...)
				}
			}

			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             nextProtos,
			}, nil

		},
	})
	go func() {
		if err := clientTlsConn.HandshakeContext(ctx); err != nil {
			errChan1 <- err
			return
		}
		close(clientHandshakeDoneChan)
	}()

	// get clientHello from client
	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		logger.Debugf("%s 客户端TLS握手失败: %v", prefix, err)
		return
	case clientHello = <-clientHelloChan:
	}
	connCtx.ClientConn.clientHello = clientHello

	if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
		cconn.Close()
		conn.Close()
		errChan2 <- err
		logger.Debugf("%s 服务器TLS握手失败: %v", prefix, err)
		return
	}
	serverTlsStateChan <- connCtx.ServerConn.tlsState

	// wait client handshake finish
	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		logger.Debugf("%s 客户端TLS握手完成等待失败: %v", prefix, err)
		return
	case <-clientHandshakeDoneChan:
	}

	// will go to attacker.ServeHTTP
	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) httpsLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request) {
	connCtx := cconn.(*wrapClientConn).connCtx
	prefix := fmt.Sprintf("[Proxy.attacker.httpsLazyAttack host=%s]", connCtx.ClientConn.Conn.RemoteAddr().String())

	clientTlsConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true, // 设置此值为 true ，确保每次都会调用下面的 GetConfigForClient 方法
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			connCtx.ClientConn.clientHello = chi
			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             []string{"http/1.1"}, // only support http/1.1
			}, nil
		},
	})
	if err := clientTlsConn.HandshakeContext(ctx); err != nil {
		cconn.Close()
		logger.Debugf("%s 延迟模式TLS握手失败: %v", prefix, err)
		return
	}

	// will go to attacker.ServeHTTP
	a.initHttpsDialFn(req)
	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) attack(res http.ResponseWriter, req *http.Request) {
	proxy := a.proxy

	prefix := fmt.Sprintf("[Proxy.attacker.attack method=%s url=%s]", req.Method, req.URL)

	reply := func(response *Response, body io.Reader) {
		if response.Header != nil {
			for key, value := range response.Header {
				for _, v := range value {
					res.Header().Add(key, v)
				}
			}
		}
		if response.close {
		}
		res.WriteHeader(response.StatusCode)

		if body != nil {
			_, err := io.Copy(res, body)
			if err != nil {
				logErr(prefix, err)
			}
		}
		if response.BodyReader != nil {
			_, err := io.Copy(res, response.BodyReader)
			if err != nil {
				logErr(prefix, err)
			}
		}
		if response.Body != nil && len(response.Body) > 0 {
			_, err := res.Write(response.Body)
			if err != nil {
				logErr(prefix, err)
			}
		}
	}

	// when addons panic
	defer func() {
		if err := recover(); err != nil {
			logger.Warnf("%s Recovered: %v", prefix, err)
		}
	}()

	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	defer f.finish()

	f.ConnContext.FlowCount.Add(1)

	rawReqUrlHost := f.Request.URL.Host
	rawReqUrlScheme := f.Request.URL.Scheme

	if proxy.onRequestheadersUntilResponse(f) {
		reply(f.Response, nil)
		return
	}

	// Read request body
	var reqBody io.Reader = req.Body
	if !f.Stream {
		reqBuf, r, err := ReaderToBuffer(req.Body, proxy.Opts.StreamLargeBodies)
		reqBody = r
		if err != nil {
			logger.Errorf("%s %v", prefix, err)
			res.WriteHeader(502)
			return
		}

		if reqBuf == nil {
			logger.Warnf("%s request body size >= %v", prefix, proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Request.Body = reqBuf

			if proxy.onRequestUntilResponse(f) {
				reply(f.Response, nil)
				return
			}
			reqBody = bytes.NewReader(f.Request.Body)
		}
	}

	reqBody = proxy.onStreamRequestModifier(f, reqBody)

	proxyReqCtx := context.WithValue(req.Context(), proxyReqCtxKey, req)
	proxyReq, err := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), reqBody)
	if err != nil {
		logger.Errorf("%s %v", prefix, err)
		res.WriteHeader(502)
		return
	}

	for key, value := range f.Request.Header {
		for _, v := range value {
			proxyReq.Header.Add(key, v)
		}
	}

	useSeparateClient := f.UseSeparateClient
	if !useSeparateClient {
		if rawReqUrlHost != f.Request.URL.Host || rawReqUrlScheme != f.Request.URL.Scheme {
			useSeparateClient = true
		}
	}

	var proxyRes *http.Response
	if useSeparateClient {
		proxyRes, err = a.client.Do(proxyReq)
	} else {
		if f.ConnContext.ServerConn == nil && f.ConnContext.dialFn != nil {
			if err := f.ConnContext.dialFn(req.Context()); err != nil {
				// Check for authentication failure
				logger.Errorf("%s %v", prefix, err)
				if strings.Contains(err.Error(), "Proxy Authentication Required") {
					httpError(res, "", http.StatusProxyAuthRequired)
					return
				}
				res.WriteHeader(502)
				return
			}
		}
		proxyRes, err = f.ConnContext.ServerConn.client.Do(proxyReq)
	}
	if err != nil {
		if err == context.Canceled {
			return
		}
		logErr(prefix, err)
		res.WriteHeader(502)
		return
	}

	if proxyRes.Close {
		f.ConnContext.closeAfterResponse = true
	}

	defer proxyRes.Body.Close()

	f.Response = &Response{
		StatusCode: proxyRes.StatusCode,
		Header:     proxyRes.Header,
		close:      proxyRes.Close,
	}

	if proxy.onResponseheadersUntilBody(f) {
		reply(f.Response, nil)
		return
	}

	// Read response body
	var resBody io.Reader = proxyRes.Body
	if !f.Stream {
		resBuf, r, err := ReaderToBuffer(proxyRes.Body, proxy.Opts.StreamLargeBodies)
		resBody = r
		if err != nil {
			logger.Errorf("%s %v", prefix, err)
			res.WriteHeader(502)
			return
		}
		if resBuf == nil {
			logger.Warnf("%s response body size >= %v", prefix, proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Response.Body = resBuf

			proxy.onResponse(f)
		}
	}
	resBody = proxy.onStreamResponseModifier(f, resBody)

	reply(f.Response, resBody)
}
