// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
)

const MetadataApi = "rpc"
const EngineApi = "engine"

// CodecOption specifies which type of messages a codec supports.
//
// Deprecated: this option is no longer honored by Server.
type CodecOption int

const (
	// OptionMethodInvocation is an indication that the codec supports RPC method calls
	OptionMethodInvocation CodecOption = 1 << iota

	// OptionSubscriptions is an indication that the codec supports RPC notifications
	OptionSubscriptions = 1 << iota // support pub sub
)

// Server is an RPC server.
type Server struct {
	services serviceRegistry
	idgen    func() ID

	mutex              sync.Mutex
	codecs             map[ServerCodec]struct{}
	run                atomic.Bool
	batchItemLimit     int
	batchResponseLimit int
	httpBodyLimit      int
	
	// 增加敏感API白名单管理
	sensitiveAPIs      map[string]bool // 敏感API列表
	whitelistedIPs     map[string]bool // IP白名单
	enableSensitiveAPI bool            // 是否启用敏感API
	
	// 速率限制
	rateLimiter        RateLimiter     // 速率限制器
}

// NewServer creates a new server instance with no registered handlers.
func NewServer() *Server {
	server := &Server{
		idgen:              randomIDGenerator(),
		codecs:             make(map[ServerCodec]struct{}),
		httpBodyLimit:      defaultBodyLimit,
		sensitiveAPIs:      make(map[string]bool),
		whitelistedIPs:     make(map[string]bool),
		enableSensitiveAPI: false, // 默认关闭敏感API
		rateLimiter:        &noopRateLimiter{}, // 默认使用空操作限制器
	}
	server.run.Store(true)
	
	// 默认将这些接口标记为敏感接口
	server.MarkSensitiveAPI("personal_")
	server.MarkSensitiveAPI("admin_")
	server.MarkSensitiveAPI("debug_")
	server.MarkSensitiveAPI("miner_")
	
	// 初始化安全日志
	if log.DefaultSecurityLogger == nil {
		logDir := "./logs/security"
		err := log.InitDefaultSecurityLogger(logDir)
		if err != nil {
			log.Warn("无法初始化安全日志", "error", err)
		}
	}
	
	// Register the default service providing meta information about the RPC service such
	// as the services and methods it offers.
	rpcService := &RPCService{server}
	server.RegisterName(MetadataApi, rpcService)
	return server
}

// SetBatchLimits sets limits applied to batch requests. There are two limits: 'itemLimit'
// is the maximum number of items in a batch. 'maxResponseSize' is the maximum number of
// response bytes across all requests in a batch.
//
// This method should be called before processing any requests via ServeCodec, ServeHTTP,
// ServeListener etc.
func (s *Server) SetBatchLimits(itemLimit, maxResponseSize int) {
	s.batchItemLimit = itemLimit
	s.batchResponseLimit = maxResponseSize
}

// SetHTTPBodyLimit sets the size limit for HTTP requests.
//
// This method should be called before processing any requests via ServeHTTP.
func (s *Server) SetHTTPBodyLimit(limit int) {
	s.httpBodyLimit = limit
}

// RegisterName creates a service for the given receiver type under the given name. When no
// methods on the given receiver match the criteria to be either an RPC method or a
// subscription an error is returned. Otherwise a new service is created and added to the
// service collection this server provides to clients.
func (s *Server) RegisterName(name string, receiver interface{}) error {
	return s.services.registerName(name, receiver)
}

// ServeCodec reads incoming requests from codec, calls the appropriate callback and writes
// the response back using the given codec. It will block until the codec is closed or the
// server is stopped. In either case the codec is closed.
//
// Note that codec options are no longer supported.
func (s *Server) ServeCodec(codec ServerCodec, options CodecOption) {
	defer codec.close()

	if !s.trackCodec(codec) {
		return
	}
	defer s.untrackCodec(codec)

	cfg := &clientConfig{
		idgen:              s.idgen,
		batchItemLimit:     s.batchItemLimit,
		batchResponseLimit: s.batchResponseLimit,
	}
	c := initClient(codec, &s.services, cfg)
	<-codec.closed()
	c.Close()
}

func (s *Server) trackCodec(codec ServerCodec) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.run.Load() {
		return false // Don't serve if server is stopped.
	}
	s.codecs[codec] = struct{}{}
	return true
}

func (s *Server) untrackCodec(codec ServerCodec) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.codecs, codec)
}

// serveSingleRequest reads and processes a single RPC request from the given codec. This
// is used to serve HTTP connections. Subscriptions and reverse calls are not allowed in
// this mode.
func (s *Server) serveSingleRequest(ctx context.Context, codec ServerCodec) {
	// Don't serve if server is stopped.
	if !s.run.Load() {
		return
	}

	h := newHandler(ctx, codec, s.idgen, &s.services, s.batchItemLimit, s.batchResponseLimit)
	h.allowSubscribe = false
	defer h.close(io.EOF, nil)

	reqs, batch, err := codec.readBatch()
	if err != nil {
		if msg := messageForReadError(err); msg != "" {
			resp := errorMessage(&invalidMessageError{msg})
			codec.writeJSON(ctx, resp, true)
		}
		return
	}
	
	// 获取客户端信息
	peerInfo := PeerInfoFromContext(ctx)
	clientIP := peerInfo.RemoteAddr
	
	// 提取IP地址（去除端口）
	clientIP = GetIPFromRequest(clientIP)
	
	// 速率限制检查
	if s.rateLimiter != nil && len(reqs) > 0 {
		// 对批处理中的所有请求进行速率限制检查
		for _, req := range reqs {
			if !s.rateLimiter.Allow(clientIP, req.Method) {
				// 记录安全事件
				log.SecurityWarn("rpc", "速率限制拒绝请求", map[string]interface{}{
					"ip": clientIP,
					"method": req.Method,
					"batch": batch,
				})
				
				// 返回错误响应
				resp := errorMessage(&rateLimitError{
					message: "请求过于频繁，请稍后再试",
				})
				codec.writeJSON(ctx, resp, true)
				return
			}
		}
	}
	
	// 检查请求中是否包含敏感API调用
	if !s.enableSensitiveAPI {
		// 检查是否有敏感API调用请求
		for _, req := range reqs {
			if s.IsSensitiveAPI(req.Method) && !s.IsIPWhitelisted(clientIP) {
				resp := errorMessage(&methodNotFoundError{req.Method})
				codec.writeJSON(ctx, resp, true)
				return
			}
		}
	}
	
	if batch {
		h.handleBatch(ctx, reqs)
	} else {
		h.handleMsg(ctx, reqs[0])
	}
}

func messageForReadError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "read timeout"
		} else {
			return "read error"
		}
	} else if err != io.EOF {
		return "parse error"
	}
	return ""
}

// Stop stops reading new requests, waits for stopPendingRequestTimeout to allow pending
// requests to finish, then closes all codecs which will cancel pending requests and
// subscriptions.
func (s *Server) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.run.CompareAndSwap(true, false) {
		log.Debug("RPC server shutting down")
		
		// 关闭所有codec
		for codec := range s.codecs {
			codec.close()
		}
		
		// 关闭速率限制器
		if s.rateLimiter != nil {
			s.rateLimiter.Close()
			s.rateLimiter = nil
		}
	}
}

// RPCService gives meta information about the server.
// e.g. gives information about the loaded modules.
type RPCService struct {
	server *Server
}

// Modules returns the list of RPC services with their version number
func (s *RPCService) Modules() map[string]string {
	s.server.services.mu.Lock()
	defer s.server.services.mu.Unlock()

	modules := make(map[string]string)
	for name := range s.server.services.services {
		modules[name] = "1.0"
	}
	return modules
}

// PeerInfo contains information about the remote end of the network connection.
//
// This is available within RPC method handlers through the context. Call
// PeerInfoFromContext to get information about the client connection related to
// the current method call.
type PeerInfo struct {
	// Transport is name of the protocol used by the client.
	// This can be "http", "ws" or "ipc".
	Transport string

	// Address of client. This will usually contain the IP address and port.
	RemoteAddr string

	// Additional information for HTTP and WebSocket connections.
	HTTP struct {
		// Protocol version, i.e. "HTTP/1.1". This is not set for WebSocket.
		Version string
		// Header values sent by the client.
		UserAgent string
		Origin    string
		Host      string
	}
}

type peerInfoContextKey struct{}

// PeerInfoFromContext returns information about the client's network connection.
// Use this with the context passed to RPC method handler functions.
//
// The zero value is returned if no connection info is present in ctx.
func PeerInfoFromContext(ctx context.Context) PeerInfo {
	info, _ := ctx.Value(peerInfoContextKey{}).(PeerInfo)
	return info
}

// MarkSensitiveAPI 将特定API前缀标记为敏感API
func (s *Server) MarkSensitiveAPI(prefix string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sensitiveAPIs[prefix] = true
}

// AddToWhitelist 将IP地址添加到白名单
func (s *Server) AddToWhitelist(ip string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.whitelistedIPs[ip] = true
}

// RemoveFromWhitelist 从白名单中移除IP地址
func (s *Server) RemoveFromWhitelist(ip string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.whitelistedIPs, ip)
}

// EnableSensitiveAPI 启用敏感API
func (s *Server) EnableSensitiveAPI(enable bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.enableSensitiveAPI = enable
}

// IsSensitiveAPI 检查API名称是否是敏感API
func (s *Server) IsSensitiveAPI(method string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	for prefix := range s.sensitiveAPIs {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// IsIPWhitelisted 检查IP是否在白名单中
func (s *Server) IsIPWhitelisted(ip string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.whitelistedIPs[ip]
}

// SetRateLimiter设置服务器的速率限制器
func (s *Server) SetRateLimiter(limiter RateLimiter) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// 如果已经有一个限制器，先关闭它
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	
	s.rateLimiter = limiter
}
