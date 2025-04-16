// Copyright 2024 The Supur Chain Authors
// This file is part of the Supur Chain library.
//
// The Supur Chain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mobile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/crypto/hkdf"
	"crypto/x509"
)

// 消息类型常量
const (
	MsgTypeData         = "DATA"         // 普通数据消息
	MsgTypeHandshake    = "HANDSHAKE"    // 握手消息
	MsgTypeReconnect    = "RECONNECT"    // 重连请求消息
	MsgTypeReconnectAck = "RECONNECT_ACK" // 重连确认消息
	MsgTypeKeepAlive    = "KEEPALIVE"    // 保活消息
	MsgTypeError        = "ERROR"        // 错误消息
)

// ConnectionState 定义节点连接状态类型
type ConnectionState int

// 连接状态常量
const (
	ConnectionStateUnknown      ConnectionState = iota // 未知状态
	ConnectionStateDisconnected                       // 断开连接
	ConnectionStateInitializing                       // 初始化中
	ConnectionStateConnected                          // 已连接
	ConnectionStateError                              // 错误状态
)

// String 将连接状态转换为字符串表示
func (cs ConnectionState) String() string {
	switch cs {
	case ConnectionStateUnknown:
		return "未知"
	case ConnectionStateDisconnected:
		return "断开连接"
	case ConnectionStateInitializing:
		return "初始化中"
	case ConnectionStateConnected:
		return "已连接"
	case ConnectionStateError:
		return "错误"
	default:
		return "无效状态"
	}
}

// ConnectionStatus 连接状态
type ConnectionStatus int

const (
	ConnectionStatusDisconnected ConnectionStatus = 0 // 断开连接
	ConnectionStatusConnecting   ConnectionStatus = 1 // 连接中
	ConnectionStatusActive       ConnectionStatus = 2 // 活跃连接
	ConnectionStatusIdle         ConnectionStatus = 3 // 空闲连接
	ConnectionStatusError        ConnectionStatus = 4 // 错误状态
)

// P2PSecurityConfig 本地P2P安全配置
type P2PSecurityConfig struct {
	EnableEndToEndEncryption bool            // 启用端到端加密
	EnableMessageSigning     bool            // 启用消息签名
	EnableReplayProtection   bool            // 启用重放保护
	AuthenticationRequired   bool            // 要求身份认证
	KeyRotationInterval      time.Duration   // 密钥轮换间隔
	NonceLifetime            time.Duration   // nonce生存时间
	TrustedKeys              map[string]bool // 可信密钥列表
	KeyExchangeTimeout       time.Duration   // 密钥交换超时时间
	MaxMessageAge            time.Duration   // 最大消息年龄
	MaxClockSkew             time.Duration   // 最大时钟偏差
	SecurityVersion          string          // 安全协议版本
	MinCompatibleVersion     string          // 最低兼容版本
	NonceSize                int             // nonce大小
	MaxTimeDiffSeconds       int             // 最大时间差秒数
	SessionKeyMaxAgeHours    int             // 会话密钥最大有效期小时数
	MaxSequenceGap           int64           // 允许的最大序列号间隔
	MessageTTLSeconds        int64           // 消息生存时间（秒）
	ClockSkewTolerance        int64           // 允许的时钟偏差（秒）
	ReconnectTimeout         time.Duration   // 重连超时时间
	MaxReconnectAttempts    int             // 最大重连尝试次数
	EnableEncryption         bool            // 启用加密
	EnableAntiReplay         bool            // 启用防重放机制
}

// P2PMessage 表示一个加密的P2P消息
type P2PMessage struct {
	SenderID      string    // 发送者ID
	RecipientID   string    // 接收者ID
	MessageType   string    // 消息类型
	Payload       []byte    // 加密负载
	Nonce         []byte    // 加密nonce
	Timestamp     time.Time // 时间戳
	SequenceNum   uint64    // 序列号(防重放)
	Signature     string    // 消息签名
	PublicKeyHint []byte    // 公钥提示(用于验证)
	Encrypted     bool      // 是否加密
	EncryptedPayload []byte  // 加密后的消息负载
}

// P2PSecurity 处理本地P2P安全
type P2PSecurity struct {
	config        *P2PSecurityConfig // 安全配置
	privateKey    *ecdsa.PrivateKey  // 本地私钥
	publicKey     *ecdsa.PublicKey   // 本地公钥
	peerKeys      map[string]*ecdsa.PublicKey // 对等节点公钥
	sessionKeys   map[string][]byte  // 会话密钥
	usedNonces    map[string]time.Time // 已使用的nonce(防重放)
	sequenceNums  map[string]uint64  // 顺序编号(防重放)
	tempExchangeKeys map[string]*ecdsa.PrivateKey // 临时密钥交换密钥
	lastReceivedSequence map[string]uint64 // 最后接收的序列号
	nonces              map[string]time.Time // 已使用的nonce(防重放)
	noncesMutex         *sync.Mutex         // 非ces访问互斥锁
	tempExchangeKeys    map[string]*ecdsa.PrivateKey // 临时密钥交换密钥
	lastSeqNums         map[string]uint64  // 顺序编号(防重放)
	seqMutex            *sync.Mutex        // 序列号访问互斥锁
	localNodeID         string             // 本地节点ID
	sessionMutex        *sync.Mutex        // 会话密钥访问互斥锁
	sessionKeyCreationTime map[string]time.Time // 会话密钥创建时间
}

// P2PSecurityManager 本地P2P安全管理器
type P2PSecurityManager struct {
	config                *SecurityConfig // 安全配置
	localNodeID           string          // 本地节点ID
	privateKey            []byte          // 本地节点私钥
	publicKey             []byte          // 本地节点公钥
	trustedNodes          map[string][]byte // 信任节点的公钥映射表
	sessionKeys           map[string][]byte // 会话密钥映射表
	sessionKeyCreationTime map[string]time.Time // 会话密钥创建时间
	sequenceNumbers       map[string]uint64 // 消息序列号计数器
	processedMessages     map[string]bool   // 已处理消息的缓存
	messageWindow         time.Duration    // 消息有效时间窗口
	mutex                 sync.RWMutex     // 读写锁
	messageHistory        map[string]map[string]time.Time // 消息历史记录
	sessionKeyTimestamps  map[string]time.Time // 会话密钥创建时间
	connectionInfo        map[string]*ConnectionInfo // 连接信息
	pendingKeyRotations   map[string]*PendingKeyRotation // 等待确认的密钥轮换
	nodeTrustInfo         map[string]*NodeTrustInfo // 节点信任信息
	messageQueue          *MessageQueue            // 消息队列
	messageProcessor      *MessageProcessor        // 消息处理器
	networkSender         func(receiverID string, data []byte) error // 网络发送函数
	deliveryCallbacks     map[string]func(messageID string, status MessageDeliveryState) // 传递回调
	deliveryMutex         sync.RWMutex           // 回调互斥锁
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	SessionKeyLength  int   // 会话密钥长度（字节）
	SessionKeyTTL     int64 // 会话密钥生存时间（秒）
	MessageTTL        int64 // 消息生存时间（秒）
	MaxClockSkew      int64 // 最大时钟偏差（秒）
	NonceLength       int   // 随机数长度（字节）
	MaxMessageHistory int   // 最大消息历史记录数
}

// NewP2PSecurityManager 创建新的P2P安全管理器
func NewP2PSecurityManager(nodeID string, privateKey, publicKey []byte, config *SecurityConfig) *P2PSecurityManager {
	if config == nil {
		// 默认安全配置
		config = &SecurityConfig{
			SessionKeyLength:  32,
			SessionKeyTTL:     86400, // 24小时
			MessageTTL:        300,   // 5分钟
			MaxClockSkew:      60,    // 1分钟
			NonceLength:       16,
			MaxMessageHistory: 1000,
		}
	}

	// 创建消息队列
	messageQueue := NewMessageQueue(1000, 3, 5*time.Second) // 队列大小1000，最大重试3次，重试延迟5秒

	sm := &P2PSecurityManager{
		config:                config,
		localNodeID:           nodeID,
		privateKey:            privateKey,
		publicKey:             publicKey,
		trustedNodes:          make(map[string][]byte),
		sessionKeys:           make(map[string][]byte),
		sessionKeyCreationTime: make(map[string]time.Time),
		sequenceNumbers:       make(map[string]uint64),
		processedMessages:     make(map[string]bool),
		messageWindow:         time.Duration(config.MessageTTL) * time.Second,
		messageHistory:        make(map[string]map[string]time.Time),
		connectionInfo:        make(map[string]*ConnectionInfo),
		pendingKeyRotations:   make(map[string]*PendingKeyRotation),
		nodeTrustInfo:         make(map[string]*NodeTrustInfo),
		messageQueue:          messageQueue,
		deliveryCallbacks:     make(map[string]func(messageID string, status MessageDeliveryState)),
	}

	// 等待网络发送函数设置后再创建消息处理器
	
	return sm
}

// SetNetworkSender 设置网络发送函数
func (sm *P2PSecurityManager) SetNetworkSender(sender func(receiverID string, data []byte) error) {
	sm.networkSender = sender
	
	// 创建并启动消息处理器
	sm.messageProcessor = NewMessageProcessor(sm.messageQueue, 10, sender) // 每秒处理10条消息
	sm.messageProcessor.Start()
}

// ReconnectState 保存节点重连信息的结构体
type ReconnectState struct {
	InitiatedTime    time.Time     // 重连发起时间
	AttemptCount     int           // 重连尝试次数
	PendingSessionKey []byte       // 等待确认的新会话密钥
	ReconnectToken   string        // 重连认证令牌
	IsInProgress     bool          // 重连过程是否正在进行
}

// SessionKeyRequest 会话密钥请求结构
type SessionKeyRequest struct {
	SenderID    string    // 发送方ID
	PublicKey   []byte    // 发送方公钥（用于密钥交换）
	Timestamp   time.Time // 请求时间戳
	Nonce       []byte    // 随机数，防止重放
	Signature   []byte    // 请求签名
}

// SessionKeyResponse 会话密钥响应结构
type SessionKeyResponse struct {
	RecipientID string    // 接收方ID
	EncryptedKey []byte   // 加密的会话密钥
	Timestamp   time.Time // 响应时间戳
	Nonce       []byte    // 随机数，防止重放
	Signature   []byte    // 响应签名
}

// SecureMessageHeader 安全消息头部
type SecureMessageHeader struct {
	Version    uint8  // 协议版本
	MessageID  string // 消息唯一ID
	SenderID   string // 发送者ID
	ReceiverID string // 接收者ID
	Timestamp  int64  // 时间戳
	PayloadLen uint32 // 负载长度
}

// Serialize 序列化消息头部
func (h *SecureMessageHeader) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// 写入版本号
	if err := binary.Write(buf, binary.BigEndian, h.Version); err != nil {
		return nil, err
	}
	
	// 写入消息ID长度和消息ID
	msgIDBytes := []byte(h.MessageID)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(msgIDBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msgIDBytes); err != nil {
		return nil, err
	}
	
	// 写入发送者ID长度和发送者ID
	senderIDBytes := []byte(h.SenderID)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(senderIDBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(senderIDBytes); err != nil {
		return nil, err
	}
	
	// 写入接收者ID长度和接收者ID
	receiverIDBytes := []byte(h.ReceiverID)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(receiverIDBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(receiverIDBytes); err != nil {
		return nil, err
	}
	
	// 写入时间戳和负载长度
	if err := binary.Write(buf, binary.BigEndian, h.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.PayloadLen); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// Deserialize 反序列化消息头部
func (h *SecureMessageHeader) Deserialize(data []byte) error {
	buf := bytes.NewReader(data)
	
	// 读取版本号
	if err := binary.Read(buf, binary.BigEndian, &h.Version); err != nil {
		return err
	}
	
	// 读取消息ID
	var msgIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &msgIDLen); err != nil {
		return err
	}
	msgIDBytes := make([]byte, msgIDLen)
	if _, err := buf.Read(msgIDBytes); err != nil {
		return err
	}
	h.MessageID = string(msgIDBytes)
	
	// 读取发送者ID
	var senderIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &senderIDLen); err != nil {
		return err
	}
	senderIDBytes := make([]byte, senderIDLen)
	if _, err := buf.Read(senderIDBytes); err != nil {
		return err
	}
	h.SenderID = string(senderIDBytes)
	
	// 读取接收者ID
	var receiverIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &receiverIDLen); err != nil {
		return err
	}
	receiverIDBytes := make([]byte, receiverIDLen)
	if _, err := buf.Read(receiverIDBytes); err != nil {
		return err
	}
	h.ReceiverID = string(receiverIDBytes)
	
	// 读取时间戳和负载长度
	if err := binary.Read(buf, binary.BigEndian, &h.Timestamp); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &h.PayloadLen); err != nil {
		return err
	}
	
	return nil
}

// SecureMessage 安全消息完整结构
type SecureMessage struct {
	Header           *SecureMessageHeader // 消息头部
	EncryptedPayload []byte               // 加密的负载
	HMAC             []byte               // 消息认证码
	Signature        []byte               // 签名
}

// Serialize 序列化完整消息
func (m *SecureMessage) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// 序列化头部
	headerBytes, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	
	// 写入头部长度和头部
	if err := binary.Write(buf, binary.BigEndian, uint16(len(headerBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(headerBytes); err != nil {
		return nil, err
	}
	
	// 写入加密负载长度和加密负载
	if err := binary.Write(buf, binary.BigEndian, uint32(len(m.EncryptedPayload))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(m.EncryptedPayload); err != nil {
		return nil, err
	}
	
	// 写入HMAC长度和HMAC
	if err := binary.Write(buf, binary.BigEndian, uint16(len(m.HMAC))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(m.HMAC); err != nil {
		return nil, err
	}
	
	// 写入签名长度和签名
	if err := binary.Write(buf, binary.BigEndian, uint16(len(m.Signature))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(m.Signature); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// DeserializeSecureMessage 反序列化完整消息
func DeserializeSecureMessage(data []byte) (*SecureMessage, error) {
	buf := bytes.NewReader(data)
	msg := &SecureMessage{
		Header: &SecureMessageHeader{},
	}
	
	// 读取头部长度和头部
	var headerLen uint16
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return nil, err
	}
	headerBytes := make([]byte, headerLen)
	if _, err := buf.Read(headerBytes); err != nil {
		return nil, err
	}
	if err := msg.Header.Deserialize(headerBytes); err != nil {
		return nil, err
	}
	
	// 读取加密负载长度和加密负载
	var payloadLen uint32
	if err := binary.Read(buf, binary.BigEndian, &payloadLen); err != nil {
		return nil, err
	}
	msg.EncryptedPayload = make([]byte, payloadLen)
	if _, err := buf.Read(msg.EncryptedPayload); err != nil {
		return nil, err
	}
	
	// 读取HMAC长度和HMAC
	var hmacLen uint16
	if err := binary.Read(buf, binary.BigEndian, &hmacLen); err != nil {
		return nil, err
	}
	msg.HMAC = make([]byte, hmacLen)
	if _, err := buf.Read(msg.HMAC); err != nil {
		return nil, err
	}
	
	// 读取签名长度和签名
	var signatureLen uint16
	if err := binary.Read(buf, binary.BigEndian, &signatureLen); err != nil {
		return nil, err
	}
	msg.Signature = make([]byte, signatureLen)
	if _, err := buf.Read(msg.Signature); err != nil {
		return nil, err
	}
	
	return msg, nil
}

// EncryptAndPackMessage 加密并打包消息
func (sm *P2PSecurityManager) EncryptAndPackMessage(recipientID string, messageType uint8, payload []byte) (*SecureMessage, error) {
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[recipientID]
	creationTime := sm.sessionKeyCreationTime[recipientID]
	sm.mutex.RUnlock()
	
	// 检查会话密钥是否存在
	if !exists {
		return nil, fmt.Errorf("无法找到与节点 %s 的会话密钥", recipientID)
	}
	
	// 检查会话密钥是否过期
	if time.Since(creationTime) > time.Duration(sm.config.SessionKeyTTL)*time.Second {
		return nil, fmt.Errorf("与节点 %s 的会话密钥已过期", recipientID)
	}
	
	// 获取下一个序列号
	nextSeq := sm.getNextSequenceNumber(recipientID)
	
	// 创建消息
	msg := &SecureMessage{
		Header: &SecureMessageHeader{
			Version:    1,
			MessageID:  sm.GenerateMessageID(recipientID, payload),
			SenderID:   sm.localNodeID,
			ReceiverID: recipientID,
			Timestamp:  time.Now().UnixNano(),
			PayloadLen: uint32(len(payload)),
		},
		EncryptedPayload: payload,
	}
	
	// 生成HMAC
	hmacKey := sm.deriveHMACKey(recipientID)
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte(msg.Header.SenderID))
	h.Write([]byte(msg.Header.ReceiverID))
	h.Write([]byte{messageType})
	h.Write([]byte(fmt.Sprintf("%d", msg.Header.Timestamp)))
	binary.Write(h, binary.BigEndian, msg.Header.SequenceNum)
	h.Write(msg.EncryptedPayload)
	msg.HMAC = h.Sum(nil)
	
	// 签名消息
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(msg.Header.SenderID))
	signData.Write([]byte(msg.Header.ReceiverID))
	signData.Write([]byte{messageType})
	signData.Write([]byte(fmt.Sprintf("%d", msg.Header.Timestamp)))
	binary.Write(signData, binary.BigEndian, msg.Header.SequenceNum)
	signData.Write(msg.EncryptedPayload)
	signData.Write(msg.HMAC)
	
	signature, err := sm.SignMessage(signData.Bytes())
	if err != nil {
		return nil, fmt.Errorf("签名消息失败: %v", err)
	}
	msg.Signature = signature
	
	return msg, nil
}

// VerifyAndUnpackMessage 验证并解包消息
func (sm *P2PSecurityManager) VerifyAndUnpackMessage(message *SecureMessage) ([]byte, error) {
	// 验证消息是否是发给本地节点的
	if message.Header.ReceiverID != sm.localNodeID && message.Header.ReceiverID != "broadcast" {
		return nil, fmt.Errorf("消息不是发给本地节点的")
	}
	
	// 验证发送方是否是可信节点
	if !sm.IsNodeTrusted(message.Header.SenderID) {
		return nil, fmt.Errorf("消息来自不受信任的节点: %s", message.Header.SenderID)
	}
	
	// 获取发送方的会话密钥
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[message.Header.SenderID]
	sm.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("无法找到与节点 %s 的会话密钥", message.Header.SenderID)
	}
	
	// 验证HMAC
	hmacKey := sm.deriveHMACKey(message.Header.SenderID)
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte(message.Header.SenderID))
	h.Write([]byte(message.Header.ReceiverID))
	h.Write([]byte{message.Header.MessageType})
	h.Write([]byte(fmt.Sprintf("%d", message.Header.Timestamp)))
	binary.Write(h, binary.BigEndian, message.Header.SequenceNum)
	h.Write(message.EncryptedPayload)
	expectedHMAC := h.Sum(nil)
	
	if !hmac.Equal(message.HMAC, expectedHMAC) {
		return nil, fmt.Errorf("HMAC验证失败")
	}
	
	// 验证签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(message.Header.SenderID))
	signData.Write([]byte(message.Header.ReceiverID))
	signData.Write([]byte{message.Header.MessageType})
	signData.Write([]byte(fmt.Sprintf("%d", message.Header.Timestamp)))
	binary.Write(signData, binary.BigEndian, message.Header.SequenceNum)
	signData.Write(message.EncryptedPayload)
	signData.Write(message.HMAC)
	
	senderPubKey, exists := sm.trustedNodes[message.Header.SenderID]
	if !exists {
		return nil, fmt.Errorf("无法获取节点 %s 的公钥", message.Header.SenderID)
	}
	
	err := sm.VerifySignature(signData.Bytes(), message.Signature, senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("签名验证失败: %v", err)
	}
	
	// 防重放攻击检查
	if err := sm.AntiReplayCheck(message.Header.SenderID, message.Header.SequenceNum, message.Header.Timestamp); err != nil {
		return nil, err
	}
	
	// 解密负载
	// 从负载中提取nonce（前12字节）
	if len(message.EncryptedPayload) < 12 {
		return nil, fmt.Errorf("无效的负载长度")
	}
	nonce := message.EncryptedPayload[:12]
	ciphertext := message.EncryptedPayload[12:]
	
	// 创建AES-GCM
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %v", err)
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}
	
	// 解密数据
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密数据失败: %v", err)
	}
	
	return plaintext, nil
}

// getNextSequenceNumber 获取下一个序列号
func (sm *P2PSecurityManager) getNextSequenceNumber(nodeID string) uint64 {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	seq := sm.sequenceNumbers[nodeID]
	seq++
	sm.sequenceNumbers[nodeID] = seq
	return seq
}

// deriveHMACKey 从会话密钥派生HMAC密钥
func (sm *P2PSecurityManager) deriveHMACKey(sessionKey []byte) []byte {
	// 使用HKDF派生新密钥
	hkdf := hkdf.New(sha256.New, sessionKey, []byte("HMAC-Key-Salt"), []byte("P2P-HMAC-Key"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(hkdf, key)
	return key
}

// AntiReplayCheck 检查消息是否为重放攻击
func (sm *P2PSecurityManager) AntiReplayCheck(senderID string, sequenceNum uint64, timestamp time.Time) error {
	// 检查时间戳是否在可接受范围内
	now := time.Now()
	maxSkew := time.Duration(sm.config.MaxClockSkew) * time.Second
	
	// 1. 检查消息是否太旧
	if timestamp.Add(sm.messageWindow).Before(now) {
		return fmt.Errorf("消息已过期")
	}
	
	// 2. 检查消息是否来自未来（时钟偏差超过允许范围）
	if timestamp.After(now.Add(maxSkew)) {
		return fmt.Errorf("消息时间戳在未来，可能是时钟同步问题或攻击")
	}
	
	// 3. 创建消息唯一标识符
	messageID := fmt.Sprintf("%s:%d:%s", senderID, sequenceNum, timestamp.Format(time.RFC3339Nano))
	
	// 4. 检查消息是否已被处理
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	if _, exists := sm.processedMessages[messageID]; exists {
		return fmt.Errorf("消息已被处理，可能是重放攻击")
	}
	
	// 5. 检查序列号是否有效
	lastSeq := sm.sequenceNumbers[senderID]
	if sequenceNum <= lastSeq {
		return fmt.Errorf("消息序列号无效，可能是重放攻击")
	}
	
	// 6. 更新最后处理的序列号
	sm.sequenceNumbers[senderID] = sequenceNum
	
	// 7. 记录已处理的消息
	sm.processedMessages[messageID] = true
	
	// 8. 清理过期的消息记录（可以定期执行或在消息数量达到阈值时执行）
	if len(sm.processedMessages) > sm.config.MaxMessageHistory {
		sm.cleanupOldMessages()
	}
	
	return nil
}

// cleanupOldMessages 清理过期消息记录
func (sm *P2PSecurityManager) cleanupOldMessages() {
	// 注意：已经在调用方法中获取了锁，此处不需要再获取
	// 创建新的映射表来替换旧的
	newProcessedMessages := make(map[string]bool)
	
	// 检查每个消息ID的时间戳，只保留最近的消息
	threshold := time.Now().Add(-sm.messageWindow)
	count := 0
	
	for msgID, _ := range sm.processedMessages {
		parts := strings.Split(msgID, ":")
		if len(parts) >= 3 {
			// 提取时间戳部分
			timestamp, err := time.Parse(time.RFC3339Nano, parts[2])
			if err == nil && timestamp.After(threshold) {
				// 只保留在时间窗口内的消息
				newProcessedMessages[msgID] = true
				count++
				
				// 如果已经达到最大历史记录数的一半，停止添加
				if count >= sm.config.MaxMessageHistory/2 {
					break
				}
			}
		}
	}
	
	// 替换旧的消息记录
	sm.processedMessages = newProcessedMessages
}

// updateSequenceNumber 更新序列号并将其添加到消息中
func (sm *P2PSecurityManager) updateSequenceNumber(nodeID string, payload []byte) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 确保消息足够长，前16字节将被用于序列号和时间戳
	if len(payload) < 16 {
		return fmt.Errorf("消息负载长度不足，无法添加序列号和时间戳")
	}
	
	// 生成新的序列号
	var newSeq uint64 = 1
	if lastSeq, exists := sm.lastSequenceNum[nodeID]; exists {
		newSeq = lastSeq + 1
	}
	
	// 写入序列号到消息的前8个字节
	binary.BigEndian.PutUint64(payload[:8], newSeq)
	
	// 写入当前时间戳到接下来的8个字节
	timestamp := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(payload[8:16], timestamp)
	
	// 更新最后发送的序列号
	sm.lastSequenceNum[nodeID] = newSeq
	
	return nil
}

// RotateSessionKey 轮换会话密钥
func (sm *P2PSecurityManager) RotateSessionKey(nodeID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 生成新的会话密钥
	newKey := make([]byte, 32) // 256位密钥
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("生成新会话密钥失败: %v", err)
	}
	
	// 更新会话密钥
	sm.sessionKeys[nodeID] = newKey
	sm.sessionKeyCreationTime[nodeID] = time.Now()
	
	// 记录轮换日志
	log.Printf("已为节点 %s 轮换会话密钥", nodeID)
	
	return nil
}

// CheckSessionKeyExpiry 检查会话密钥是否过期
func (sm *P2PSecurityManager) CheckSessionKeyExpiry() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now()
	
	// 检查所有会话密钥
	for nodeID, creationTime := range sm.sessionKeyCreationTime {
		if sm.config.SessionKeyMaxAgeHours > 0 && now.Sub(creationTime) > time.Duration(sm.config.SessionKeyMaxAgeHours)*time.Hour {
			// 密钥已过期，标记为需要轮换
			log.Printf("节点 %s 的会话密钥已过期，标记为需要轮换", nodeID)
			sm.pendingKeyRotation[nodeID] = true
		}
	}
}

// GetPendingKeyRotations 获取需要轮换密钥的节点列表
func (sm *P2PSecurityManager) GetPendingKeyRotations() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	var nodes []string
	for nodeID, needsRotation := range sm.pendingKeyRotation {
		if needsRotation {
			nodes = append(nodes, nodeID)
		}
	}
	
	return nodes
}

// ClearPendingKeyRotation 清除节点的密钥轮换标记
func (sm *P2PSecurityManager) ClearPendingKeyRotation(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	delete(sm.pendingKeyRotation, nodeID)
}

// NewP2PSecurity 创建新的P2P安全实例
func NewP2PSecurity(config *P2PSecurityConfig) (*P2PSecurity, error) {
	// 生成新的ECDSA密钥对
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成ECDSA密钥失败: %v", err)
	}

	return &P2PSecurity{
		config:        config,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		peerKeys:      make(map[string]*ecdsa.PublicKey),
		sessionKeys:   make(map[string][]byte),
		usedNonces:    make(map[string]time.Time),
		sequenceNums:  make(map[string]uint64),
		tempExchangeKeys: make(map[string]*ecdsa.PrivateKey),
		lastReceivedSequence: make(map[string]uint64),
		nonces:              make(map[string]time.Time),
		noncesMutex:         &sync.Mutex{},
		tempExchangeKeys:    make(map[string]*ecdsa.PrivateKey),
		lastSeqNums:         make(map[string]uint64),
		seqMutex:            &sync.Mutex{},
		sessionMutex:        &sync.Mutex{},
		sessionKeyCreationTime: make(map[string]time.Time),
	}, nil
}

// EncryptMessage 加密P2P消息
func (ps *P2PSecurity) EncryptMessage(recipientID string, msgType string, payload []byte) (*P2PMessage, error) {
	// 检查是否有接收方公钥
	recipientKey, exists := ps.peerKeys[recipientID]
	if !exists {
		return nil, errors.New("没有接收方公钥")
	}

	// 生成或获取会话密钥
	sessionKey, err := ps.getOrCreateSessionKey(recipientID)
	if err != nil {
		return nil, err
	}

	// 生成随机nonce
	nonce := make([]byte, 12) // AES-GCM建议使用12字节nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 加密消息
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// 获取下一个序列号
	sequenceNum := ps.getNextSequenceNumber(recipientID)
	
	// 关联数据(AAD) - 包含元数据防篡改
	aad := []byte(fmt.Sprintf("%s-%s-%d", ps.getPublicKeyHex(), recipientID, sequenceNum))
	
	// 加密(包含认证)
	encryptedPayload := aesgcm.Seal(nil, nonce, payload, aad)
	
	// 创建消息对象
	msg := &P2PMessage{
		SenderID:      ps.getPublicKeyHex(),
		RecipientID:   recipientID,
		MessageType:   msgType,
		Payload:       encryptedPayload,
		Nonce:         nonce,
		Timestamp:     time.Now(),
		SequenceNum:   sequenceNum,
		PublicKeyHint: crypto.FromECDSAPub(ps.publicKey)[:10], // 只存储公钥前缀作为提示
	}
	
	// 签名消息
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(msg); err != nil {
			return nil, err
		}
	}
	
	return msg, nil
}

// DecryptMessage 解密收到的P2P消息
func (ps *P2PSecurity) DecryptMessage(msg *P2PMessage) ([]byte, error) {
	// 验证消息签名
	if ps.config.EnableMessageSigning && msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return nil, fmt.Errorf("消息签名验证失败: %v", err)
		}
	}
	
	// 检查重放攻击
	if ps.config.EnableReplayProtection {
		nonceStr := hex.EncodeToString(msg.Nonce)
		if timestamp, used := ps.usedNonces[nonceStr]; used {
			// 检查nonce是否已过期 - 如果过期，则允许重用
			if time.Since(timestamp) < ps.config.NonceLifetime {
				return nil, errors.New("检测到重放攻击:重复的nonce")
			}
			// nonce已过期，可以重用
			delete(ps.usedNonces, nonceStr)
		}
		
		// 检查序列号
		expectedSeq, ok := ps.sequenceNums[msg.SenderID]
		if ok && msg.SequenceNum < expectedSeq {
			return nil, fmt.Errorf("序列号无效: 收到 %d，期望 >= %d", msg.SequenceNum, expectedSeq)
		}
		
		// 记录此nonce已被使用
		ps.usedNonces[nonceStr] = time.Now()
		
		// 更新序列号
		if msg.SequenceNum >= expectedSeq {
			ps.sequenceNums[msg.SenderID] = msg.SequenceNum + 1
		}
	}
	
	// 获取会话密钥
	sessionKey, exists := ps.sessionKeys[msg.SenderID]
	if !exists {
		return nil, errors.New("没有发送方的会话密钥")
	}
	
	// 解密消息
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// 重建关联数据AAD
	aad := []byte(fmt.Sprintf("%s-%s-%d", msg.SenderID, ps.getPublicKeyHex(), msg.SequenceNum))
	
	// 解密并验证
	decrypted, err := aesgcm.Open(nil, msg.Nonce, msg.Payload, aad)
	if err != nil {
		return nil, fmt.Errorf("解密失败(可能的篡改): %v", err)
	}
	
	return decrypted, nil
}

// getOrCreateSessionKey 获取或创建与指定对等节点的会话密钥
func (ps *P2PSecurity) getOrCreateSessionKey(peerID string) ([]byte, error) {
	// 检查是否已有会话密钥
	ps.sessionMutex.Lock()
	sessionKey, exists := ps.sessionKeys[peerID]
	
	// 如果存在有效会话密钥，直接返回
	if exists && ps.isSessionKeyValid(peerID) {
		ps.sessionMutex.Unlock()
		return sessionKey, nil
	}
	
	// 获取对等节点的公钥
	peerKey, hasPeerKey := ps.peerKeys[peerID]
	if !hasPeerKey {
		ps.sessionMutex.Unlock()
		return nil, fmt.Errorf("未找到节点 %s 的公钥", peerID)
	}
	
	// 使用ECDH创建共享密钥
	sharedKey, err := ps.computeSharedSecret(peerKey)
	if err != nil {
		ps.sessionMutex.Unlock()
		return nil, err
	}
	
	// 从共享密钥派生会话密钥
	derivedKey := ps.deriveSessionKey(sharedKey, []byte(peerID+ps.localNodeID))
	
	// 更新会话密钥
	ps.sessionKeys[peerID] = derivedKey
	
	// 设置会话密钥创建时间
	ps.sessionKeyCreationTime[peerID] = time.Now()
	
	ps.sessionMutex.Unlock()
	return derivedKey, nil
}

// computeSharedSecret 计算ECDH共享秘密
func (ps *P2PSecurity) computeSharedSecret(peerPublicKey *ecdsa.PublicKey) ([]byte, error) {
	// 从公钥创建椭圆曲线点
	publicX, publicY := peerPublicKey.X, peerPublicKey.Y
	
	// 计算共享点
	sx, sy := elliptic.P256().ScalarMult(publicX, publicY, ps.privateKey.D.Bytes())
	
	// 将共享点的x坐标作为共享秘密
	sharedSecret := crypto.Keccak256(sx.Bytes())
	
	return sharedSecret, nil
}

// deriveSessionKey 从共享秘密派生会话密钥
func (ps *P2PSecurity) deriveSessionKey(sharedSecret, salt []byte) []byte {
	// 使用HKDF-SHA256派生密钥
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("P2PSessionKey"))
	
	// 创建AES-256密钥（32字节）
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		log.Printf("派生会话密钥时出错: %v", err)
		return nil
	}
	
	return key
}

// isSessionKeyValid 检查会话密钥是否仍然有效
func (ps *P2PSecurity) isSessionKeyValid(peerID string) bool {
	// 获取密钥创建时间
	createTime, exists := ps.sessionKeyCreationTime[peerID]
	if !exists {
		return false
	}
	
	// 检查是否超过会话密钥最大有效期
	return time.Since(createTime) < time.Duration(ps.config.SessionKeyMaxAgeHours) * time.Hour
}

// RotateSessionKey 强制轮换与特定对等节点的会话密钥
func (ps *P2PSecurity) RotateSessionKey(peerID string) error {
	ps.sessionMutex.Lock()
	defer ps.sessionMutex.Unlock()
	
	// 检查是否存在该对等节点
	if _, exists := ps.peerKeys[peerID]; !exists {
		return fmt.Errorf("未找到节点 %s 的公钥信息", peerID)
	}
	
	// 删除现有的会话密钥和创建时间
	delete(ps.sessionKeys, peerID)
	delete(ps.sessionKeyCreationTime, peerID)
	
	// 创建新的会话密钥
	_, err := ps.getOrCreateSessionKey(peerID)
	return err
}

// RotateAllSessionKeys 轮换所有会话密钥
func (ps *P2PSecurity) RotateAllSessionKeys() {
	ps.sessionMutex.Lock()
	
	// 记录需要轮换的对等节点ID
	var peersToRotate []string
	for peerID := range ps.sessionKeys {
		peersToRotate = append(peersToRotate, peerID)
	}
	
	ps.sessionMutex.Unlock()
	
	// 轮换每个对等节点的会话密钥
	for _, peerID := range peersToRotate {
		if err := ps.RotateSessionKey(peerID); err != nil {
			log.Printf("轮换节点 %s 的会话密钥失败: %v", peerID, err)
		}
	}
}

// VerifySecurityVersion 验证安全协议版本
func (ps *P2PSecurity) VerifySecurityVersion(remoteVersion string) (bool, error) {
	// 解析版本号
	localMajor, localMinor, localPatch, err := parseVersionString(ps.config.SecurityVersion)
	if err != nil {
		return false, fmt.Errorf("解析本地版本失败: %v", err)
	}
	
	remoteMajor, remoteMinor, remotePatch, err := parseVersionString(remoteVersion)
	if err != nil {
		return false, fmt.Errorf("解析远程版本失败: %v", err)
	}
	
	// 检查主版本号是否匹配
	if localMajor != remoteMajor {
		return false, fmt.Errorf("主版本号不匹配: 本地 %d, 远程 %d", localMajor, remoteMajor)
	}
	
	// 如果本地设置了最低兼容版本
	if ps.config.MinCompatibleVersion != "" {
		minMajor, minMinor, minPatch, err := parseVersionString(ps.config.MinCompatibleVersion)
		if err != nil {
			return false, fmt.Errorf("解析最低兼容版本失败: %v", err)
		}
		
		// 检查远程版本是否大于等于最低兼容版本
		if remoteMajor < minMajor || 
		   (remoteMajor == minMajor && remoteMinor < minMinor) ||
		   (remoteMajor == minMajor && remoteMinor == minMinor && remotePatch < minPatch) {
			return false, fmt.Errorf("远程版本 %s 低于最低兼容版本 %s", 
				remoteVersion, ps.config.MinCompatibleVersion)
		}
	}
	
	return true, nil
}

// parseVersionString 解析版本字符串(如"1.2.3")为主、次、补丁版本号
func parseVersionString(version string) (major, minor, patch int, err error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("无效的版本格式: %s", version)
	}
	
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("无效的主版本号: %s", parts[0])
	}
	
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("无效的次版本号: %s", parts[1])
	}
	
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("无效的补丁版本号: %s", parts[2])
	}
	
	return major, minor, patch, nil
}

// CheckMessageFreshness 检查消息是否过期或过早
func (ps *P2PSecurity) CheckMessageFreshness(msg *P2PMessage) error {
	// 获取当前时间
	now := time.Now().UnixNano()
	msgTime := msg.Timestamp
	
	// 计算时间差（单位：秒）
	diffSeconds := math.Abs(float64(now - msgTime)) / 1e9
	
	// 如果消息时间超过允许的偏差范围
	if diffSeconds > float64(ps.config.MaxTimeDiffSeconds) {
		return fmt.Errorf("消息时间戳无效，时间差为 %.2f 秒，超过允许的 %d 秒",
			diffSeconds, ps.config.MaxTimeDiffSeconds)
	}
	
	return nil
}

// signMessage 为消息添加签名
func (ps *P2PSecurity) signMessage(msg *P2PMessage) error {
	// 创建消息摘要
	contentHash := ps.hashMessageContent(msg)
	
	// 使用私钥签名
	signature, err := crypto.Sign(contentHash, ps.privateKey)
	if err != nil {
		return fmt.Errorf("签名失败: %v", err)
	}
	
	// 将签名转换为十六进制字符串
	msg.Signature = hex.EncodeToString(signature)
	return nil
}

// verifyMessageSignature 验证消息签名
func (ps *P2PSecurity) verifyMessageSignature(msg *P2PMessage) error {
	// 获取发送方公钥
	sender, err := ps.resolveSenderPublicKey(msg)
	if err != nil {
		return err
	}
	
	// 重建待签名数据
	signData := ps.buildSignatureData(msg)
	
	// 计算数据哈希
	dataHash := crypto.Keccak256Hash(signData)
	
	// 验证签名
	sigPublicKey, err := crypto.Ecrecover(dataHash.Bytes(), msg.Signature)
	if err != nil {
		return err
	}
	
	senderBytes := crypto.FromECDSAPub(sender)
	
	// 比较恢复的公钥和发送方公钥
	if !bytes.Equal(sigPublicKey, senderBytes) {
		return errors.New("签名不匹配")
	}
	
	return nil
}

// buildSignatureData 构建用于签名的数据
func (ps *P2PSecurity) buildSignatureData(msg *P2PMessage) []byte {
	// 构建包含消息所有相关字段的签名数据(不包括签名本身)
	buffer := new(bytes.Buffer)
	buffer.WriteString(msg.SenderID)
	buffer.WriteString(msg.RecipientID)
	buffer.WriteString(msg.MessageType)
	buffer.Write(msg.Payload)
	buffer.Write(msg.Nonce)
	buffer.WriteString(msg.Timestamp.Format(time.RFC3339Nano))
	buffer.WriteString(fmt.Sprintf("%d", msg.SequenceNum))
	return buffer.Bytes()
}

// resolveSenderPublicKey 解析发送方公钥
func (ps *P2PSecurity) resolveSenderPublicKey(msg *P2PMessage) (*ecdsa.PublicKey, error) {
	// 检查是否已知此发送方
	if pubKey, exists := ps.peerKeys[msg.SenderID]; exists {
		return pubKey, nil
	}
	
	// 当我们没有发送方公钥时，消息应包含足够的提示
	if msg.PublicKeyHint == nil || len(msg.PublicKeyHint) == 0 {
		return nil, errors.New("无法解析发送方公钥:缺少公钥提示")
	}
	
	// 在实际实现中，可能需要通过网络请求或其他方式获取公钥
	return nil, errors.New("未知发送方")
}

// getPublicKeyHex 获取本地公钥的十六进制表示
func (ps *P2PSecurity) getPublicKeyHex() string {
	publicKeyBytes := crypto.FromECDSAPub(ps.publicKey)
	return common.Bytes2Hex(publicKeyBytes)
}

// getNextSequenceNumber 获取用于通信的下一个序列号
func (ps *P2PSecurity) getNextSequenceNumber(peerID string) uint64 {
	seq, exists := ps.sequenceNums[peerID]
	if !exists {
		// 首次通信，从1开始
		seq = 1
	} else {
		// 增加序列号
		seq++
	}
	ps.sequenceNums[peerID] = seq
	return seq
}

// RotateKeys 定期轮换密钥
func (ps *P2PSecurity) RotateKeys() error {
	// 生成新的ECDSA密钥对
	newPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("生成新ECDSA密钥失败: %v", err)
	}
	
	// 保存旧密钥用于过渡期
	oldPrivateKey := ps.privateKey
	oldPublicKey := ps.publicKey
	
	// 更新当前密钥
	ps.privateKey = newPrivateKey
	ps.publicKey = &newPrivateKey.PublicKey
	
	// 清除会话密钥缓存，这将触发重新协商
	ps.sessionKeys = make(map[string][]byte)
	
	log.Info("P2P安全密钥已轮换")
	
	return nil
}

// RegisterPeer 注册新的对等节点
func (ps *P2PSecurity) RegisterPeer(peerID string, publicKey *ecdsa.PublicKey) error {
	// 验证参数
	if peerID == "" {
		return errors.New("节点ID不能为空")
	}
	if publicKey == nil {
		return errors.New("公钥不能为空")
	}

	// 检查是否已经注册
	if _, exists := ps.peerKeys[peerID]; exists {
		return fmt.Errorf("节点 %s 已经注册", peerID)
	}

	// 存储对等节点的公钥
	ps.peerKeys[peerID] = publicKey
	log.Info("已注册新节点", "节点ID", peerID)
	
	return nil
}

// AuthenticatePeer 认证对等节点
func (ps *P2PSecurity) AuthenticatePeer(peerID string, challenge []byte, signature []byte) (bool, error) {
	// 获取对等节点的公钥
	peerKey, exists := ps.peerKeys[peerID]
	if !exists {
		return false, errors.New("未知节点")
	}
	
	// 计算挑战的哈希值
	challengeHash := crypto.Keccak256Hash(challenge)
	
	// 验证签名
	sigPublicKey, err := crypto.Ecrecover(challengeHash.Bytes(), signature)
	if err != nil {
		return false, err
	}
	
	peerKeyBytes := crypto.FromECDSAPub(peerKey)
	
	// 比较恢复的公钥和已注册的公钥
	if !bytes.Equal(sigPublicKey, peerKeyBytes) {
		return false, nil // 签名无效
	}
	
	return true, nil // 认证成功
}

// GenerateChallenge 生成用于认证的随机挑战
func (ps *P2PSecurity) GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

// SignChallenge 签名认证挑战
func (ps *P2PSecurity) SignChallenge(challenge []byte) ([]byte, error) {
	if challenge == nil || len(challenge) == 0 {
		return nil, errors.New("挑战不能为空")
	}
	
	// 计算挑战的哈希值
	challengeHash := crypto.Keccak256Hash(challenge)
	
	// 使用私钥签名
	signature, err := crypto.Sign(challengeHash.Bytes(), ps.privateKey)
	if err != nil {
		return nil, err
	}
	
	return signature, nil
}

// InitiateKeyExchange 发起密钥交换
func (ps *P2PSecurity) InitiateKeyExchange(peerID string) (*P2PMessage, error) {
	// 创建临时ECDH密钥对
	tempPrivKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时ECDH密钥失败: %v", err)
	}
	
	// 序列化临时公钥
	tempPubKeyBytes := crypto.FromECDSAPub(&tempPrivKey.PublicKey)
	
	// 创建密钥交换请求消息
	msg := &P2PMessage{
		SenderID:    ps.getPublicKeyHex(),
		RecipientID: peerID,
		MessageType: "KEY_EXCHANGE_REQUEST",
		Payload:     tempPubKeyBytes,
		Timestamp:   time.Now(),
		Nonce:       make([]byte, 12),
		SequenceNum: ps.getNextSequenceNumber(peerID),
		PublicKeyHint: crypto.FromECDSAPub(ps.publicKey),
	}
	
	// 生成随机nonce
	if _, err := rand.Read(msg.Nonce); err != nil {
		return nil, err
	}
	
	// 签名消息
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(msg); err != nil {
			return nil, err
		}
	}
	
	// 存储临时私钥，用于后续处理响应
	ps.tempExchangeKeys[peerID] = tempPrivKey
	
	return msg, nil
}

// HandleKeyExchangeRequest 处理密钥交换请求
func (ps *P2PSecurity) HandleKeyExchangeRequest(msg *P2PMessage) (*P2PMessage, error) {
	// 验证请求签名
	if ps.config.EnableMessageSigning && msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return nil, fmt.Errorf("密钥交换请求签名验证失败: %v", err)
		}
	}
	
	// 解析请求方的临时公钥
	tempPubKey, err := crypto.UnmarshalPubkey(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("解析临时公钥失败: %v", err)
	}
	
	// 创建我们自己的临时ECDH密钥对
	ourTempPrivKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时ECDH密钥失败: %v", err)
	}
	
	// 计算共享密钥
	x, _ := tempPubKey.Curve.ScalarMult(tempPubKey.X, tempPubKey.Y, ourTempPrivKey.D.Bytes())
	if x == nil {
		return nil, errors.New("ECDH密钥派生失败")
	}
	
	// 派生会话密钥
	shared := x.Bytes()
	hash := sha256.Sum256(shared)
	sessionKey := hash[:]
	
	// 保存会话密钥
	ps.sessionKeys[msg.SenderID] = sessionKey
	
	// 序列化我们的临时公钥
	ourTempPubKeyBytes := crypto.FromECDSAPub(&ourTempPrivKey.PublicKey)
	
	// 创建密钥交换响应消息
	response := &P2PMessage{
		SenderID:    ps.getPublicKeyHex(),
		RecipientID: msg.SenderID,
		MessageType: "KEY_EXCHANGE_RESPONSE",
		Payload:     ourTempPubKeyBytes,
		Timestamp:   time.Now(),
		Nonce:       make([]byte, 12),
		SequenceNum: ps.getNextSequenceNumber(msg.SenderID),
		PublicKeyHint: crypto.FromECDSAPub(ps.publicKey),
	}
	
	// 生成随机nonce
	if _, err := rand.Read(response.Nonce); err != nil {
		return nil, err
	}
	
	// 签名响应
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(response); err != nil {
			return nil, err
		}
	}
	
	log.Info("已处理密钥交换请求并生成响应", "对等节点", msg.SenderID)
	return response, nil
}

// HandleKeyExchangeResponse 处理密钥交换响应
func (ps *P2PSecurity) HandleKeyExchangeResponse(msg *P2PMessage) error {
	// 验证响应签名
	if ps.config.EnableMessageSigning && msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return fmt.Errorf("密钥交换响应签名验证失败: %v", err)
		}
	}
	
	// 获取之前存储的临时私钥
	tempPrivKey, exists := ps.tempExchangeKeys[msg.SenderID]
	if !exists {
		return errors.New("没有找到对应的密钥交换请求记录")
	}
	
	// 清理临时私钥存储
	defer delete(ps.tempExchangeKeys, msg.SenderID)
	
	// 解析响应中的临时公钥
	tempPubKey, err := crypto.UnmarshalPubkey(msg.Payload)
	if err != nil {
		return fmt.Errorf("解析临时公钥失败: %v", err)
	}
	
	// 计算共享密钥
	x, _ := tempPubKey.Curve.ScalarMult(tempPubKey.X, tempPubKey.Y, tempPrivKey.D.Bytes())
	if x == nil {
		return errors.New("ECDH密钥派生失败")
	}
	
	// 派生会话密钥
	shared := x.Bytes()
	hash := sha256.Sum256(shared)
	sessionKey := hash[:]
	
	// 保存会话密钥
	ps.sessionKeys[msg.SenderID] = sessionKey
	
	log.Info("密钥交换完成", "对等节点", msg.SenderID)
	return nil
}

// EncryptMessage 加密消息
func (ps *P2PSecurity) EncryptMessage(msg *P2PMessage) error {
	if msg == nil {
		return errors.New("消息不能为空")
	}
	
	// 如果需要签名，先签名消息
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(msg); err != nil {
			return err
		}
	}
	
	// 获取会话密钥
	sessionKey, exists := ps.sessionKeys[msg.RecipientID]
	if !exists {
		return fmt.Errorf("获取会话密钥失败: %v", err)
	}
	
	// 序列化原始数据
	plaintext, err := json.Marshal(map[string]interface{}{
		"type":      msg.MessageType,
		"payload":   msg.Payload,
		"timestamp": msg.Timestamp,
		"signature": msg.Signature,
		"sequence":  msg.SequenceNum,
	})
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}
	
	// 创建AES-GCM加密器
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("创建加密器失败: %v", err)
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("创建GCM模式失败: %v", err)
	}
	
	// 加密消息
	ciphertext := aesgcm.Seal(nil, msg.Nonce, plaintext, nil)
	msg.EncryptedPayload = ciphertext
	
	// 清除明文数据
	msg.Payload = nil
	msg.Signature = ""
	
	// 设置加密标志
	msg.Encrypted = true
	
	return nil
}

// DecryptMessage 解密消息
func (ps *P2PSecurity) DecryptMessage(msg *P2PMessage) error {
	if msg == nil {
		return errors.New("消息不能为空")
	}
	
	if !msg.Encrypted || msg.EncryptedPayload == nil {
		return errors.New("消息未加密")
	}
	
	// 获取会话密钥
	sessionKey, exists := ps.sessionKeys[msg.SenderID]
	if !exists {
		return errors.New("没有对应的会话密钥")
	}
	
	// 创建AES-GCM加密器
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("创建解密器失败: %v", err)
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("创建GCM模式失败: %v", err)
	}
	
	// 解密消息
	plaintext, err := aesgcm.Open(nil, msg.Nonce, msg.EncryptedPayload, nil)
	if err != nil {
		return fmt.Errorf("解密失败: %v", err)
	}
	
	// 解析解密后的数据
	var decryptedData map[string]interface{}
	if err := json.Unmarshal(plaintext, &decryptedData); err != nil {
		return fmt.Errorf("解析解密数据失败: %v", err)
	}
	
	// 恢复消息字段
	if messageType, ok := decryptedData["type"].(string); ok {
		msg.MessageType = messageType
	}
	
	if payload, ok := decryptedData["payload"].([]byte); ok {
		msg.Payload = payload
	} else if payloadJSON, ok := decryptedData["payload"]; ok {
		// 处理JSON格式的载荷
		payloadBytes, err := json.Marshal(payloadJSON)
		if err != nil {
			return fmt.Errorf("转换载荷格式失败: %v", err)
		}
		msg.Payload = payloadBytes
	}
	
	if signature, ok := decryptedData["signature"].(string); ok {
		msg.Signature = signature
	} else if signatureJSON, ok := decryptedData["signature"]; ok {
		// 处理JSON格式的签名
		signatureBytes, err := json.Marshal(signatureJSON)
		if err != nil {
			return fmt.Errorf("转换签名格式失败: %v", err)
		}
		msg.Signature = hex.EncodeToString(signatureBytes)
	}
	
	if sequence, ok := decryptedData["sequence"].(float64); ok {
		msg.SequenceNum = uint64(sequence)
	}
	
	if timestamp, ok := decryptedData["timestamp"].(string); ok {
		parsedTime, err := time.Parse(time.RFC3339, timestamp)
		if err == nil {
			msg.Timestamp = parsedTime
		}
	}
	
	// 清除加密数据
	msg.EncryptedPayload = nil
	msg.Encrypted = false
	
	// 如果启用了签名验证，验证消息签名
	if ps.config.EnableMessageSigning && msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return fmt.Errorf("签名验证失败: %v", err)
		}
	}
	
	// 验证消息序列号以防止重放攻击
	if err := ps.verifySequenceNumber(msg); err != nil {
		return err
	}
	
	return nil
}

// 验证消息序列号以防止重放攻击
func (ps *P2PSecurity) verifySequenceNumber(msg *P2PMessage) error {
	ps.seqMutex.Lock()
	defer ps.seqMutex.Unlock()
	
	senderID := msg.SenderID
	lastSeq, exists := ps.lastSeqNums[senderID]
	
	// 如果是新发送者，先记录序列号
	if !exists {
		ps.lastSeqNums[senderID] = msg.SequenceNum
		return nil
	}
	
	// 检查序列号是否增加
	if msg.SequenceNum <= lastSeq {
		return fmt.Errorf("消息序列号过期或重放攻击: 当前 %d, 上次 %d", 
			msg.SequenceNum, lastSeq)
	}
	
	// 更新最新序列号
	ps.lastSeqNums[senderID] = msg.SequenceNum
	return nil
}

// createNonce 创建一个随机nonce
func (ps *P2PSecurity) createNonce() (string, error) {
	// 生成随机字节
	nonceBytes := make([]byte, ps.config.NonceSize)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		return "", fmt.Errorf("生成nonce失败: %v", err)
	}
	
	// 转换为十六进制字符串
	nonce := hex.EncodeToString(nonceBytes)
	
	// 存储nonce及其创建时间
	ps.noncesMutex.Lock()
	ps.nonces[nonce] = time.Now()
	ps.noncesMutex.Unlock()
	
	// 启动垃圾收集
	go ps.cleanExpiredNonces()
	
	return nonce, nil
}

// cleanExpiredNonces 清理过期的nonce
func (ps *P2PSecurity) cleanExpiredNonces() {
	ps.noncesMutex.Lock()
	defer ps.noncesMutex.Unlock()
	
	now := time.Now()
	for nonce, creationTime := range ps.nonces {
		if now.Sub(creationTime) > ps.config.NonceLifetime {
			delete(ps.nonces, nonce)
		}
	}
}

// RegisterPeerKey 注册对等节点的公钥
func (ps *P2PSecurity) RegisterPeerKey(peerID string, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return errors.New("提供的公钥为空")
	}
	
	// 验证peerID是否与公钥匹配
	pubKeyBytes := crypto.FromECDSAPub(publicKey)
	derivedPeerID := hex.EncodeToString(crypto.Keccak256(pubKeyBytes)[:20])
	
	if peerID != derivedPeerID {
		return fmt.Errorf("peerID不匹配: 提供的ID %s, 从公钥派生的ID %s", 
			peerID, derivedPeerID)
	}
	
	// 存储公钥
	ps.peerKeys[peerID] = publicKey
	log.Info("注册了对等节点公钥", "对等节点", peerID)
	
	return nil
}

// IsTrustedPeer 检查对等节点是否受信任
func (ps *P2PSecurity) IsTrustedPeer(peerID string) bool {
	// 检查是否在可信列表中
	if ps.config.TrustedKeys != nil {
		if trusted, exists := ps.config.TrustedKeys[peerID]; exists && trusted {
			return true
		}
	}
	
	// 检查是否有注册的公钥
	_, hasPeerKey := ps.peerKeys[peerID]
	return hasPeerKey
}

// VerifyMessageIntegrity 验证消息的完整性和真实性
func (ps *P2PSecurity) VerifyMessageIntegrity(msg *P2PMessage) error {
	// 1. 验证消息时间戳
	if err := ps.CheckMessageFreshness(msg); err != nil {
		return err
	}
	
	// 2. 验证序列号（防重放）
	if err := ps.verifySequenceNumber(msg); err != nil {
		return err
	}
	
	// 3. 如果有nonce，验证其有效性
	if msg.Nonce != "" {
		ps.noncesMutex.Lock()
		_, exists := ps.nonces[msg.Nonce]
		ps.noncesMutex.Unlock()
		
		if exists {
			return errors.New("nonce已被使用，可能是重放攻击")
		}
	}
	
	// 4. 验证签名
	if msg.Signature == "" {
		return errors.New("消息未签名")
	}
	
	// 获取发送者公钥
	senderPublicKey, exists := ps.peerKeys[msg.SenderID]
	if !exists {
		return fmt.Errorf("未知的发送者: %s", msg.SenderID)
	}
	
	// 创建需要验证的消息内容哈希
	contentHash := ps.hashMessageContent(msg)
	
	// 解码签名
	sigBytes, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return fmt.Errorf("无效的签名格式: %v", err)
	}
	
	// 验证签名
	valid := crypto.VerifySignature(
		crypto.FromECDSAPub(senderPublicKey),
		contentHash,
		sigBytes[:len(sigBytes)-1], // 去掉恢复ID
	)
	
	if !valid {
		return errors.New("签名验证失败")
	}
	
	return nil
}

// hashMessageContent 对消息内容进行哈希
func (ps *P2PSecurity) hashMessageContent(msg *P2PMessage) []byte {
	// 创建一个包含所有相关字段的消息摘要
	content := fmt.Sprintf("%s:%s:%d:%d:%s:%s",
		msg.SenderID,
		msg.RecipientID,
		msg.SequenceNum,
		msg.Timestamp,
		msg.MessageType,
		msg.Payload,
	)
	
	// 计算摘要的SHA3-256哈希
	return crypto.Keccak256([]byte(content))
}

// EncryptMessage 使用会话密钥加密消息
func (ps *P2PSecurity) EncryptMessage(recipientID string, msgType string, payload []byte) (*P2PMessage, error) {
	// 检查接收者ID
	if recipientID == "" {
		return nil, errors.New("接收者ID不能为空")
	}
	
	// 获取或创建会话密钥
	sessionKey, err := ps.getOrCreateSessionKey(recipientID)
	if err != nil {
		return nil, fmt.Errorf("获取会话密钥失败: %v", err)
	}
	
	// 创建nonce
	nonce, err := ps.createNonce()
	if err != nil {
		return nil, fmt.Errorf("创建nonce失败: %v", err)
	}
	
	// 创建消息结构
	msg := &P2PMessage{
		SenderID:     ps.localNodeID,
		RecipientID:  recipientID,
		SequenceNum:  ps.getNextSequenceNumber(),
		Timestamp:    time.Now().UnixNano(),
		MessageType:  msgType,
		Nonce:        nonce,
		Encrypted:    true,
		SecurityVer:  ps.config.SecurityVersion,
	}
	
	// 加密消息内容
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建加密器失败: %v", err)
	}
	
	// 使用GCM模式进行认证加密
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM加密模式失败: %v", err)
	}
	
	// 创建随机数（用于加密，不同于消息nonce）
	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, fmt.Errorf("生成加密nonce失败: %v", err)
	}
	
	// 加密数据
	ciphertext := gcm.Seal(nil, nonceBytes, payload, nil)
	
	// 将nonce和加密数据合并
	encryptedPayload := append(nonceBytes, ciphertext...)
	msg.Payload = hex.EncodeToString(encryptedPayload)
	
	// 签名消息
	if err := ps.signMessage(msg); err != nil {
		return nil, fmt.Errorf("签名消息失败: %v", err)
	}
	
	return msg, nil
}

// DecryptMessage 解密收到的消息
func (ps *P2PSecurity) DecryptMessage(msg *P2PMessage) ([]byte, error) {
	// 验证消息的完整性和真实性
	if err := ps.VerifyMessageIntegrity(msg); err != nil {
		return nil, err
	}
	
	// 如果消息未加密，直接返回载荷
	if !msg.Encrypted {
		payloadBytes, err := hex.DecodeString(msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("解码未加密载荷失败: %v", err)
		}
		return payloadBytes, nil
	}
	
	// 获取与发送者的会话密钥
	sessionKey, exists := ps.sessionKeys[msg.SenderID]
	if !exists {
		return nil, fmt.Errorf("未找到与发送者的会话密钥: %s", msg.SenderID)
	}
	
	// 解码加密的载荷
	encryptedData, err := hex.DecodeString(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("解码加密载荷失败: %v", err)
	}
	
	// 创建解密器
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建解密器失败: %v", err)
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM解密模式失败: %v", err)
	}
	
	// 检查加密数据长度是否合理
	if len(encryptedData) < gcm.NonceSize() {
		return nil, errors.New("加密数据长度不足")
	}
	
	// 分离nonce和密文
	nonceBytes := encryptedData[:gcm.NonceSize()]
	ciphertext := encryptedData[gcm.NonceSize():]
	
	// 解密数据
	plaintext, err := gcm.Open(nil, nonceBytes, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}
	
	return plaintext, nil
}

// getNextSequenceNumber 获取下一个序列号
func (ps *P2PSecurity) getNextSequenceNumber() uint64 {
	ps.seqMutex.Lock()
	defer ps.seqMutex.Unlock()
	
	// 基于当前时间戳和一个随机增量创建序列号
	timestamp := uint64(time.Now().UnixNano())
	random := uint64(rand.Intn(1000))
	
	return timestamp + random
}

// AntiReplayCheck 防重放攻击检查
func (ps *P2PSecurity) AntiReplayCheck(msg *P2PMessage, senderID string) error {
	ps.seqMutex.Lock()
	defer ps.seqMutex.Unlock()
	
	// 获取最后一个序列号
	lastSeq, exists := ps.lastSeqNums[senderID]
	
	// 如果是来自此发送者的第一条消息，只需要记录序列号
	if !exists {
		ps.lastSeqNums[senderID] = msg.SequenceNum
		return nil
	}
	
	// 检查序列号是否重复或无效
	if msg.SequenceNum <= lastSeq {
		return fmt.Errorf("检测到重放攻击：收到的序列号 %d 小于或等于上一个序列号 %d",
			msg.SequenceNum, lastSeq)
	}
	
	// 检查序列号跳跃是否过大（可能表示攻击或通信问题）
	seqGap := msg.SequenceNum - lastSeq
	if seqGap > ps.config.MaxSequenceGap {
		return fmt.Errorf("序列号跳跃过大：跳跃了 %d，最大允许值为 %d",
			seqGap, ps.config.MaxSequenceGap)
	}
	
	// 更新最新序列号
	ps.lastSeqNums[senderID] = msg.SequenceNum
	return nil
}

// InitiateReconnection 初始化与对等节点的重新连接过程
func (ps *P2PSecurity) InitiateReconnection(peerID string) error {
	// 创建重连消息
	reconnMsg := &P2PMessage{
		MessageType:  MsgTypeReconnect,
		SenderID:     ps.localNodeID,
		RecipientID:  peerID,
		Timestamp:    time.Now().UnixNano(),
		SequenceNum:  ps.getNextSequenceNumber(),
		Payload:      []byte{},
		Encrypted:    false,
		NetworkID:    ps.networkID,
	}
	
	// 为消息添加签名
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(reconnMsg); err != nil {
			return fmt.Errorf("对重连消息签名失败: %v", err)
		}
	}
	
	// 发送重连消息到对等节点
	// 注意：这里需要利用提供的回调函数发送消息
	if ps.onSendMessage != nil {
		return ps.onSendMessage(reconnMsg)
	}
	
	return fmt.Errorf("无法发送重连消息：未设置发送回调函数")
}

// HandleReconnectionRequest 处理对等节点的重连请求
func (ps *P2PSecurity) HandleReconnectionRequest(msg *P2PMessage) (*P2PMessage, error) {
	senderID := msg.SenderID
	
	// 验证发送者身份
	if msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return nil, fmt.Errorf("重连请求签名验证失败: %v", err)
		}
	}
	
	// 重置与该对等节点的序列号记录
	ps.seqMutex.Lock()
	delete(ps.lastSeqNums, senderID)
	ps.seqMutex.Unlock()
	
	// 轮换该对等节点的会话密钥
	if err := ps.RotateSessionKey(senderID); err != nil {
		log.Warn("重连过程中轮换会话密钥失败", "对等节点", senderID, "错误", err)
		// 继续处理，因为这不是致命错误
	}
	
	// 创建重连响应
	response := &P2PMessage{
		MessageType:  MsgTypeReconnectAck,
		SenderID:     ps.localNodeID,
		RecipientID:  senderID,
		Timestamp:    time.Now().UnixNano(),
		SequenceNum:  ps.getNextSequenceNumber(),
		Payload:      []byte{},
		Encrypted:    false,
		NetworkID:    ps.networkID,
	}
	
	// 为响应添加签名
	if ps.config.EnableMessageSigning {
		if err := ps.signMessage(response); err != nil {
			return nil, fmt.Errorf("对重连响应签名失败: %v", err)
		}
	}
	
	return response, nil
}

// HandleReconnectionAcknowledgement 处理重连确认消息
func (ps *P2PSecurity) HandleReconnectionAcknowledgement(msg *P2PMessage) error {
	senderID := msg.SenderID
	
	// 验证发送者身份
	if msg.Signature != "" {
		if err := ps.verifyMessageSignature(msg); err != nil {
			return fmt.Errorf("重连确认签名验证失败: %v", err)
		}
	}
	
	// 重置重连状态
	ps.seqMutex.Lock()
	delete(ps.lastSeqNums, senderID)
	ps.seqMutex.Unlock()
	
	log.Info("与对等节点重连成功", "对等节点", senderID)
	return nil
}

// GetPeerConnectionState 获取与对等节点的连接状态
func (ps *P2PSecurity) GetPeerConnectionState(peerID string) (ConnectionState, error) {
	// 检查是否有该对等节点的公钥
	if _, exists := ps.peerKeys[peerID]; !exists {
		return ConnectionStateUnknown, fmt.Errorf("未知的对等节点: %s", peerID)
	}
	
	// 检查是否有会话密钥
	ps.sessionMutex.Lock()
	_, hasSessionKey := ps.sessionKeys[peerID]
	ps.sessionMutex.Unlock()
	
	if !hasSessionKey {
		return ConnectionStateDisconnected, nil
	}
	
	// 检查是否有最近的序列号记录
	ps.seqMutex.Lock()
	_, hasSequence := ps.lastSeqNums[peerID]
	ps.seqMutex.Unlock()
	
	if !hasSequence {
		return ConnectionStateInitializing, nil
	}
	
	return ConnectionStateConnected, nil
}

// UpdateConnectionState 更新节点连接状态
func (sm *P2PSecurityManager) UpdateConnectionState(nodeID string, state ConnectionState) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 初始化连接状态映射（如果还未初始化）
	if sm.connectionState == nil {
		sm.connectionState = make(map[string]ConnectionState)
	}
	
	prevState, exists := sm.connectionState[nodeID]
	
	// 更新连接状态
	sm.connectionState[nodeID] = state
	
	// 记录状态变化日志
	if !exists || prevState != state {
		log.Printf("节点 %s 连接状态从 %s 变为 %s", nodeID, prevState.String(), state.String())
	}
	
	// 如果状态变为已连接，重置该节点的重连状态
	if state == ConnectionStateConnected {
		if sm.reconnectState != nil {
			if _, exists := sm.reconnectState[nodeID]; exists {
				delete(sm.reconnectState, nodeID)
			}
		}
	}
}

// GetConnectionState 获取节点当前连接状态
func (sm *P2PSecurityManager) GetConnectionState(nodeID string) ConnectionState {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	if sm.connectionState == nil {
		return ConnectionStateUnknown
	}
	
	state, exists := sm.connectionState[nodeID]
	if !exists {
		return ConnectionStateUnknown
	}
	
	return state
}

// InitiateReconnect 发起与节点的重连
func (sm *P2PSecurityManager) InitiateReconnect(nodeID string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 检查当前节点连接状态
	currentState := ConnectionStateUnknown
	if sm.connectionState != nil {
		if state, exists := sm.connectionState[nodeID]; exists {
			currentState = state
		}
	}
	
	// 如果节点已连接，返回错误
	if currentState == ConnectionStateConnected {
		return "", fmt.Errorf("节点 %s 已连接，无需重连", nodeID)
	}
	
	// 初始化重连状态映射（如果还未初始化）
	if sm.reconnectState == nil {
		sm.reconnectState = make(map[string]*ReconnectState)
	}
	
	// 检查已有重连尝试
	var reconnState *ReconnectState
	if existingState, exists := sm.reconnectState[nodeID]; exists {
		reconnState = existingState
		
		// 检查重连尝试次数是否超过限制
		if reconnState.AttemptCount >= sm.config.MaxReconnectAttempts {
			return "", fmt.Errorf("节点 %s 重连失败：尝试次数已达上限 %d", 
				nodeID, sm.config.MaxReconnectAttempts)
		}
		
		// 检查上次重连是否超时
		if reconnState.IsInProgress && 
		   time.Since(reconnState.InitiatedTime) < time.Duration(sm.config.ReconnectTimeout)*time.Second {
			return "", fmt.Errorf("节点 %s 重连正在进行中，请稍后再试", nodeID)
		}
		
		// 增加重连尝试次数
		reconnState.AttemptCount++
	} else {
		// 创建新的重连状态
		reconnState = &ReconnectState{
			AttemptCount: 1,
			IsInProgress: true,
		}
		sm.reconnectState[nodeID] = reconnState
	}
	
	// 更新重连状态
	reconnState.InitiatedTime = time.Now()
	
	// 生成新的会话密钥和重连令牌
	newSessionKey, err := sm.generateSessionKey()
	if err != nil {
		return "", fmt.Errorf("生成新会话密钥失败: %v", err)
	}
	
	// 生成重连令牌（简单实现为随机字符串）
	reconnToken := fmt.Sprintf("%s-%d-%s", nodeID, time.Now().UnixNano(), 
		randomStringWithSource(16, rand.NewSource(time.Now().UnixNano())))
	
	// 保存等待确认的会话密钥和重连令牌
	reconnState.PendingSessionKey = newSessionKey
	reconnState.ReconnectToken = reconnToken
	
	// 将连接状态设置为初始化中
	if sm.connectionState == nil {
		sm.connectionState = make(map[string]ConnectionState)
	}
	sm.connectionState[nodeID] = ConnectionStateInitializing
	
	return reconnToken, nil
}

// CompleteReconnect 完成与节点的重连过程
func (sm *P2PSecurityManager) CompleteReconnect(nodeID string, reconnToken string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 检查是否存在重连状态
	if sm.reconnectState == nil {
		return fmt.Errorf("节点 %s 没有待处理的重连", nodeID)
	}
	
	reconnState, exists := sm.reconnectState[nodeID]
	if !exists || !reconnState.IsInProgress {
		return fmt.Errorf("节点 %s 没有进行中的重连", nodeID)
	}
	
	// 验证重连令牌
	if reconnState.ReconnectToken != reconnToken {
		return fmt.Errorf("重连令牌验证失败")
	}
	
	// 检查重连是否超时
	if time.Since(reconnState.InitiatedTime) > time.Duration(sm.config.ReconnectTimeout)*time.Second {
		reconnState.IsInProgress = false
		sm.connectionState[nodeID] = ConnectionStateError
		return fmt.Errorf("重连超时")
	}
	
	// 应用新的会话密钥
	sm.sessionKeys[nodeID] = reconnState.PendingSessionKey
	sm.sessionKeyCreationTime[nodeID] = time.Now()
	
	// 更新连接状态为已连接
	sm.connectionState[nodeID] = ConnectionStateConnected
	
	// 清理重连状态
	delete(sm.reconnectState, nodeID)
	
	// 重置防重放状态
	if sm.sequenceCache != nil && sm.lastSequenceNum != nil {
		if _, exists := sm.sequenceCache[nodeID]; exists {
			sm.sequenceCache[nodeID] = make(map[int64]bool)
		}
		delete(sm.lastSequenceNum, nodeID)
	}
	
	return nil
}

// randomStringWithSource 使用特定随机源生成随机字符串
func randomStringWithSource(length int, source rand.Source) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(source)
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateSessionKeyRequest 生成会话密钥请求
func (sm *P2PSecurityManager) GenerateSessionKeyRequest(targetNodeID string) (*SessionKeyRequest, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 生成随机数
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成随机数失败: %v", err)
	}
	
	// 创建请求
	request := &SessionKeyRequest{
		SenderID:  sm.localNodeID,
		PublicKey: sm.localPublicKey,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}
	
	// 创建签名数据
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(request.SenderID))
	signData.Write(request.PublicKey)
	signData.Write([]byte(request.Timestamp.Format(time.RFC3339)))
	signData.Write(request.Nonce)
	
	// 签名请求
	signature, err := sm.SignMessage(signData.Bytes())
	if err != nil {
		return nil, fmt.Errorf("签名密钥请求失败: %v", err)
	}
	request.Signature = signature
	
	return request, nil
}

// VerifyAndProcessKeyRequest 验证并处理会话密钥请求
func (sm *P2PSecurityManager) VerifyAndProcessKeyRequest(request *SessionKeyRequest) (*SessionKeyResponse, error) {
	// 验证请求时间戳
	if time.Since(request.Timestamp) > time.Duration(sm.config.KeyRequestTTL)*time.Second {
		return nil, fmt.Errorf("密钥请求已过期")
	}
	
	// 检查请求的发送方是否在可信节点列表中
	if !sm.IsNodeTrusted(request.SenderID) {
		return nil, fmt.Errorf("密钥请求来自不受信任的节点: %s", request.SenderID)
	}
	
	// 验证请求签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(request.SenderID))
	signData.Write(request.PublicKey)
	signData.Write([]byte(request.Timestamp.Format(time.RFC3339)))
	signData.Write(request.Nonce)
	
	// 获取发送方的公钥
	senderPubKey, exists := sm.trustedNodes[request.SenderID]
	if !exists {
		return nil, fmt.Errorf("无法获取节点 %s 的公钥", request.SenderID)
	}
	
	// 验证签名
	err := sm.VerifySignature(signData.Bytes(), request.Signature, senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("验证密钥请求签名失败: %v", err)
	}
	
	// 生成新的会话密钥
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("生成会话密钥失败: %v", err)
	}
	
	// 存储会话密钥
	sm.mutex.Lock()
	sm.sessionKeys[request.SenderID] = sessionKey
	sm.sessionKeyCreationTime[request.SenderID] = time.Now()
	sm.mutex.Unlock()
	
	// 使用请求者的公钥加密会话密钥
	encryptedKey, err := sm.EncryptWithPublicKey(sessionKey, request.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("加密会话密钥失败: %v", err)
	}
	
	// 生成随机数
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成随机数失败: %v", err)
	}
	
	// 创建响应
	response := &SessionKeyResponse{
		RecipientID:  request.SenderID,
		EncryptedKey: encryptedKey,
		Timestamp:    time.Now(),
		Nonce:        nonce,
	}
	
	// 创建签名数据
	respSignData := bytes.NewBuffer(nil)
	respSignData.Write([]byte(response.RecipientID))
	respSignData.Write(response.EncryptedKey)
	respSignData.Write([]byte(response.Timestamp.Format(time.RFC3339)))
	respSignData.Write(response.Nonce)
	
	// 签名响应
	signature, err := sm.SignMessage(respSignData.Bytes())
	if err != nil {
		return nil, fmt.Errorf("签名密钥响应失败: %v", err)
	}
	response.Signature = signature
	
	return response, nil
}

// VerifyAndProcessKeyResponse 验证并处理会话密钥响应
func (sm *P2PSecurityManager) VerifyAndProcessKeyResponse(response *SessionKeyResponse) error {
	// 验证响应时间戳
	if time.Since(response.Timestamp) > time.Duration(sm.config.KeyResponseTTL)*time.Second {
		return fmt.Errorf("密钥响应已过期")
	}
	
	// 检查接收方ID是否匹配本地节点ID
	if response.RecipientID != sm.localNodeID {
		return fmt.Errorf("密钥响应接收方ID不匹配: 期望 %s, 收到 %s", 
			sm.localNodeID, response.RecipientID)
	}
	
	// 创建签名数据
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(response.RecipientID))
	signData.Write(response.EncryptedKey)
	signData.Write([]byte(response.Timestamp.Format(time.RFC3339)))
	signData.Write(response.Nonce)
	
	// 获取发送方的公钥（假设响应来自目标节点）
	senderID := "" // 需要从上下文中推断出发送方ID
	senderPubKey, exists := sm.trustedNodes[senderID]
	if !exists {
		return fmt.Errorf("无法获取发送方的公钥")
	}
	
	// 验证签名
	err := sm.VerifySignature(signData.Bytes(), response.Signature, senderPubKey)
	if err != nil {
		return fmt.Errorf("验证密钥响应签名失败: %v", err)
	}
	
	// 解密会话密钥
	sessionKey, err := sm.DecryptWithPrivateKey(response.EncryptedKey)
	if err != nil {
		return fmt.Errorf("解密会话密钥失败: %v", err)
	}
	
	// 存储会话密钥
	sm.mutex.Lock()
	sm.sessionKeys[senderID] = sessionKey
	sm.sessionKeyCreationTime[senderID] = time.Now()
	sm.mutex.Unlock()
	
	return nil
}

// IsNodeTrusted 检查节点是否在可信列表中
func (sm *P2PSecurityManager) IsNodeTrusted(nodeID string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	_, exists := sm.trustedNodes[nodeID]
	return exists
}

// EncryptWithPublicKey 使用公钥加密数据
func (sm *P2PSecurityManager) EncryptWithPublicKey(data []byte, publicKey []byte) ([]byte, error) {
	// 解析公钥
	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %v", err)
	}
	
	// 根据公钥类型进行加密
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// RSA加密
		return rsa.EncryptPKCS1v15(rand.Reader, key, data)
	case *ecdsa.PublicKey:
		// 对于ECDSA，我们需要实现ECIES或使用混合加密（这里简化处理）
		return nil, fmt.Errorf("暂不支持ECDSA公钥加密")
	default:
		return nil, fmt.Errorf("不支持的公钥类型")
	}
}

// DecryptWithPrivateKey 使用私钥解密数据
func (sm *P2PSecurityManager) DecryptWithPrivateKey(encryptedData []byte) ([]byte, error) {
	switch key := sm.localPrivateKey.(type) {
	case *rsa.PrivateKey:
		// RSA解密
		return rsa.DecryptPKCS1v15(rand.Reader, key, encryptedData)
	case *ecdsa.PrivateKey:
		// 对于ECDSA，需要ECIES或混合解密（简化处理）
		return nil, fmt.Errorf("暂不支持ECDSA私钥解密")
	default:
		return nil, fmt.Errorf("不支持的私钥类型")
	}
}

// EstablishSessionKey 建立与目标节点的安全会话密钥
func (sm *P2PSecurityManager) EstablishSessionKey(targetNodeID string, targetPubKey []byte) ([]byte, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 检查是否已有有效的会话密钥
	if key, exists := sm.sessionKeys[targetNodeID]; exists {
		// 检查会话密钥是否过期
		createTime, _ := sm.sessionKeyCreationTime[targetNodeID]
		if time.Since(createTime).Seconds() < float64(sm.config.SessionKeyTTL) {
			// 会话密钥未过期，可继续使用
			return key, nil
		}
		// 过期了，需要重新生成
	}
	
	// 生成新的随机会话密钥
	sessionKey := make([]byte, sm.config.SessionKeyLength)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("生成会话密钥失败: %v", err)
	}
	
	// 使用目标节点的公钥加密会话密钥
	encryptedKey, err := sm.encryptWithPublicKey(sessionKey, targetPubKey)
	if err != nil {
		return nil, fmt.Errorf("加密会话密钥失败: %v", err)
	}
	
	// 存储会话密钥和创建时间
	sm.sessionKeys[targetNodeID] = sessionKey
	sm.sessionKeyCreationTime[targetNodeID] = time.Now()
	
	// 重置与该节点的序列号计数器
	sm.sequenceNumbers[targetNodeID] = 0
	
	return encryptedKey, nil
}

// ReceiveSessionKey 接收并处理来自其他节点的会话密钥
func (sm *P2PSecurityManager) ReceiveSessionKey(senderNodeID string, encryptedKey []byte) error {
	// 验证发送方是否为信任节点
	if _, trusted := sm.trustedNodes[senderNodeID]; !trusted {
		return fmt.Errorf("来自未信任节点的会话密钥请求")
	}
	
	// 使用本地私钥解密会话密钥
	sessionKey, err := sm.decryptWithPrivateKey(encryptedKey)
	if err != nil {
		return fmt.Errorf("解密会话密钥失败: %v", err)
	}
	
	// 验证会话密钥长度
	if len(sessionKey) != sm.config.SessionKeyLength {
		return fmt.Errorf("会话密钥长度无效")
	}
	
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 存储会话密钥和创建时间
	sm.sessionKeys[senderNodeID] = sessionKey
	sm.sessionKeyCreationTime[senderNodeID] = time.Now()
	
	// 重置与该节点的序列号计数器
	sm.sequenceNumbers[senderNodeID] = 0
	
	return nil
}

// RefreshSessionKey 刷新指定节点的会话密钥
func (sm *P2PSecurityManager) RefreshSessionKey(nodeID string) ([]byte, error) {
	// 获取目标节点的公钥
	targetPubKey, exists := sm.trustedNodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("未找到目标节点的公钥")
	}
	
	// 强制重新生成会话密钥
	sm.mutex.Lock()
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyCreationTime, nodeID)
	sm.mutex.Unlock()
	
	// 使用现有方法重新建立会话密钥
	return sm.EstablishSessionKey(nodeID, targetPubKey)
}

// IsSessionKeyValid 检查与指定节点的会话密钥是否有效
func (sm *P2PSecurityManager) IsSessionKeyValid(nodeID string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	// 检查是否存在会话密钥
	key, exists := sm.sessionKeys[nodeID]
	if !exists || len(key) == 0 {
		return false
	}
	
	// 检查会话密钥是否过期
	createTime, timeExists := sm.sessionKeyCreationTime[nodeID]
	if !timeExists {
		return false
	}
	
	// 检查是否超过会话密钥的有效期
	return time.Since(createTime).Seconds() < float64(sm.config.SessionKeyTTL)
}

// RevokeSessionKey 撤销与指定节点的会话密钥
func (sm *P2PSecurityManager) RevokeSessionKey(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 删除会话密钥和相关数据
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyCreationTime, nodeID)
	delete(sm.sequenceNumbers, nodeID)
}

// TrustNode 将节点添加到信任列表
func (sm *P2PSecurityManager) TrustNode(nodeID string, publicKey []byte) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	sm.trustedNodes[nodeID] = publicKey
}

// RemoveTrustedNode 从信任列表中移除节点
func (sm *P2PSecurityManager) RemoveTrustedNode(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 从信任列表中删除
	delete(sm.trustedNodes, nodeID)
	
	// 同时删除相关的会话信息
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyCreationTime, nodeID)
	delete(sm.sequenceNumbers, nodeID)
}

// GetNextSequenceNumber 获取发送给指定节点的下一个序列号
func (sm *P2PSecurityManager) GetNextSequenceNumber(nodeID string) uint64 {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 增加序列号
	seqNum := sm.sequenceNumbers[nodeID] + 1
	sm.sequenceNumbers[nodeID] = seqNum
	
	return seqNum
}

// encryptWithPublicKey 使用公钥加密数据
func (sm *P2PSecurityManager) encryptWithPublicKey(data []byte, publicKey []byte) ([]byte, error) {
	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %v", err)
	}
	
	// 类型断言为RSA公钥
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是有效的RSA公钥")
	}
	
	// 使用RSA-OAEP进行加密
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPub,
		data,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("RSA加密失败: %v", err)
	}
	
	return ciphertext, nil
}

// decryptWithPrivateKey 使用私钥解密数据
func (sm *P2PSecurityManager) decryptWithPrivateKey(encryptedData []byte) ([]byte, error) {
	// 使用RSA-OAEP进行解密
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		sm.privateKey,
		encryptedData,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("RSA解密失败: %v", err)
	}
	
	return plaintext, nil
}

// EncryptMessage 使用会话密钥加密消息
func (sm *P2PSecurityManager) EncryptMessage(nodeID string, message []byte) ([]byte, error) {
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[nodeID]
	sm.mutex.RUnlock()
	
	if !exists || len(sessionKey) == 0 {
		return nil, fmt.Errorf("未找到与节点 %s 的有效会话密钥", nodeID)
	}
	
	// 生成随机初始化向量
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("生成初始化向量失败: %v", err)
	}
	
	// 创建AES-256-CBC加密器
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES加密器失败: %v", err)
	}
	
	// 对消息进行填充，使其长度为AES块大小的倍数
	paddedMessage := sm.pkcs7Pad(message, aes.BlockSize)
	
	// 加密消息
	ciphertext := make([]byte, len(paddedMessage))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedMessage)
	
	// 将IV与密文合并
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)
	
	return result, nil
}

// DecryptMessage 使用会话密钥解密消息
func (sm *P2PSecurityManager) DecryptMessage(nodeID string, encryptedMessage []byte) ([]byte, error) {
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[nodeID]
	sm.mutex.RUnlock()
	
	if !exists || len(sessionKey) == 0 {
		return nil, fmt.Errorf("未找到与节点 %s 的有效会话密钥", nodeID)
	}
	
	// 检查加密消息长度是否合法
	if len(encryptedMessage) < aes.BlockSize {
		return nil, fmt.Errorf("加密消息长度不足")
	}
	
	// 提取IV和密文
	iv := encryptedMessage[:aes.BlockSize]
	ciphertext := encryptedMessage[aes.BlockSize:]
	
	// 创建AES-256-CBC解密器
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES解密器失败: %v", err)
	}
	
	// 解密消息
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	
	// 去除填充
	unpadded, err := sm.pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("去除填充失败: %v", err)
	}
	
	return unpadded, nil
}

// pkcs7Pad 使用PKCS#7算法对数据进行填充
func (sm *P2PSecurityManager) pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// pkcs7Unpad 使用PKCS#7算法去除数据填充
func (sm *P2PSecurityManager) pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("数据长度为0")
	}
	
	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return nil, fmt.Errorf("填充长度无效")
	}
	
	// 验证填充值是否一致
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("填充格式无效")
		}
	}
	
	return data[:len(data)-padLen], nil
}

// SignMessage 对消息进行签名
func (sm *P2PSecurityManager) SignMessage(message []byte) ([]byte, error) {
	// 使用私钥对消息的哈希值进行签名
	messageHash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, sm.privateKey, crypto.SHA256, messageHash[:])
	if err != nil {
		return nil, fmt.Errorf("签名失败: %v", err)
	}
	return signature, nil
}

// VerifySignature 验证消息签名
func (sm *P2PSecurityManager) VerifySignature(nodeID string, message, signature []byte) error {
	sm.mutex.RLock()
	publicKey, trusted := sm.trustedNodes[nodeID]
	sm.mutex.RUnlock()
	
	if !trusted || len(publicKey) == 0 {
		return fmt.Errorf("节点 %s 不在信任列表中", nodeID)
	}
	
	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	// 类型断言为RSA公钥
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("公钥不是有效的RSA公钥")
	}
	
	// 计算消息哈希
	messageHash := sha256.Sum256(message)
	
	// 验证签名
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, messageHash[:], signature)
	if err != nil {
		return fmt.Errorf("签名验证失败: %v", err)
	}
	
	return nil
}

// AddMessageToHistory 添加消息到历史记录防止重放攻击
func (sm *P2PSecurityManager) AddMessageToHistory(nodeID string, messageID string) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 如果节点的消息历史记录不存在，则创建
	if _, exists := sm.messageHistory[nodeID]; !exists {
		sm.messageHistory[nodeID] = make(map[string]time.Time)
	}
	
	// 检查消息是否已经存在（即重放攻击）
	if _, exists := sm.messageHistory[nodeID][messageID]; exists {
		return false // 消息已处理过，可能是重放攻击
	}
	
	// 添加消息到历史记录，记录接收时间
	sm.messageHistory[nodeID][messageID] = time.Now()
	
	// 清理过期的消息历史记录
	sm.cleanupMessageHistory(nodeID)
	
	return true // 消息是新的，可以处理
}

// cleanupMessageHistory 清理过期的消息历史记录
func (sm *P2PSecurityManager) cleanupMessageHistory(nodeID string) {
	current := time.Now()
	for messageID, timestamp := range sm.messageHistory[nodeID] {
		// 如果消息接收时间超过保留时间（例如10分钟），则删除
		if current.Sub(timestamp) > 10*time.Minute {
			delete(sm.messageHistory[nodeID], messageID)
		}
	}
}

// GenerateMessageID 为消息生成唯一ID
func (sm *P2PSecurityManager) GenerateMessageID(nodeID string, message []byte) string {
	// 获取当前序列号
	seqNum := sm.GetNextSequenceNumber(nodeID)
	
	// 组合节点ID、消息内容和序列号生成唯一的消息ID
	h := sha256.New()
	h.Write([]byte(nodeID))
	h.Write(message)
	binary.Write(h, binary.BigEndian, seqNum)
	
	// 返回16进制编码的哈希值作为消息ID
	return hex.EncodeToString(h.Sum(nil))
}

// CreateSecureMessage 创建安全消息封装
func (sm *P2PSecurityManager) CreateSecureMessage(nodeID string, payload []byte) ([]byte, error) {
	// 检查会话密钥是否有效
	if !sm.IsSessionKeyValid(nodeID) {
		return nil, fmt.Errorf("无有效会话密钥")
	}
	
	// 生成消息ID
	messageID := sm.GenerateMessageID(nodeID, payload)
	
	// 获取当前时间戳
	timestamp := time.Now().UnixNano()
	
	// 创建消息头部
	header := &SecureMessageHeader{
		Version:    1,
		MessageID:  messageID,
		SenderID:   sm.nodeID,
		ReceiverID: nodeID,
		Timestamp:  timestamp,
		PayloadLen: uint32(len(payload)),
	}
	
	// 序列化头部
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, err
	}
	
	// 计算头部和负载的HMAC
	hmacKey := sm.deriveHMACKey(nodeID)
	h := hmac.New(sha256.New, hmacKey)
	h.Write(headerBytes)
	h.Write(payload)
	mac := h.Sum(nil)
	
	// 加密负载
	encryptedPayload, err := sm.EncryptMessage(nodeID, payload)
	if err != nil {
		return nil, err
	}
	
	// 对整个消息进行签名
	signatureMessage := append(headerBytes, encryptedPayload...)
	signatureMessage = append(signatureMessage, mac...)
	signature, err := sm.SignMessage(signatureMessage)
	if err != nil {
		return nil, err
	}
	
	// 构建完整消息
	message := &SecureMessage{
		Header:           header,
		EncryptedPayload: encryptedPayload,
		HMAC:             mac,
		Signature:        signature,
	}
	
	// 序列化完整消息
	return message.Serialize()
}

// deriveHMACKey 从会话密钥派生HMAC密钥
func (sm *P2PSecurityManager) deriveHMACKey(nodeID string) []byte {
	sm.mutex.RLock()
	sessionKey := sm.sessionKeys[nodeID]
	sm.mutex.RUnlock()
	
	// 使用HKDF从会话密钥派生HMAC密钥
	salt := []byte("HMAC-Key-Derivation")
	info := []byte(fmt.Sprintf("%s:%s:hmac", sm.nodeID, nodeID))
	
	r := hkdf.New(sha256.New, sessionKey, salt, info)
	hmacKey := make([]byte, 32) // 256位密钥
	_, err := io.ReadFull(r, hmacKey)
	if err != nil {
		log.Error("派生HMAC密钥失败", "error", err)
		return nil
	}
	
	return hmacKey
}

// EncryptPayload 加密消息负载
func (sm *P2PSecurityManager) EncryptPayload(nodeID string, payload []byte) ([]byte, error) {
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[nodeID]
	sm.mutex.RUnlock()
	
	if !exists || len(sessionKey) == 0 {
		return nil, fmt.Errorf("没有找到与节点 %s 的会话密钥", nodeID)
	}
	
	// 使用AES-GCM模式加密
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %v", err)
	}
	
	// 生成随机数（Nonce）
	nonce := make([]byte, 12) // GCM模式推荐12字节的nonce
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成随机数失败: %v", err)
	}
	
	// 创建GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}
	
	// 加密数据 (将nonce附加在加密数据之前)
	encryptedData := aesgcm.Seal(nonce, nonce, payload, nil)
	return encryptedData, nil
}

// DecryptPayload 解密消息负载
func (sm *P2PSecurityManager) DecryptPayload(nodeID string, encryptedData []byte) ([]byte, error) {
	sm.mutex.RLock()
	sessionKey, exists := sm.sessionKeys[nodeID]
	sm.mutex.RUnlock()
	
	if !exists || len(sessionKey) == 0 {
		return nil, fmt.Errorf("没有找到与节点 %s 的会话密钥", nodeID)
	}
	
	// 检查加密数据的长度
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("加密数据长度不足")
	}
	
	// 提取nonce和密文
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]
	
	// 使用AES-GCM模式解密
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %v", err)
	}
	
	// 创建GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}
	
	// 解密
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}
	
	return plaintext, nil
}

// EstablishSession 建立与其他节点的安全会话
func (sm *P2PSecurityManager) EstablishSession(remoteNodeID string, remotePubKey *rsa.PublicKey) error {
	// 检查是否已经存在会话
	sm.mutex.RLock()
	_, exists := sm.sessionKeys[remoteNodeID]
	sm.mutex.RUnlock()
	
	if exists {
		// 如果会话已经存在，检查是否需要刷新
		if sm.IsSessionKeyValid(remoteNodeID) {
			return nil // 会话有效，不需要重新建立
		}
	}
	
	// 生成新的会话密钥（AES-256）
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return fmt.Errorf("生成会话密钥失败: %v", err)
	}
	
	// 使用远程节点的公钥加密会话密钥
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		remotePubKey,
		sessionKey,
		[]byte("session-key"),
	)
	if err != nil {
		return fmt.Errorf("加密会话密钥失败: %v", err)
	}
	
	// 创建会话建立消息
	sessionMsg := &SessionEstablishMessage{
		SenderID:            sm.localNodeID,
		ReceiverID:          remoteNodeID,
		EncryptedSessionKey: encryptedSessionKey,
		Timestamp:           time.Now().UnixNano(),
	}
	
	// 签名会话消息
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(sessionMsg.SenderID))
	signData.Write([]byte(sessionMsg.ReceiverID))
	signData.Write(sessionMsg.EncryptedSessionKey)
	binary.Write(signData, binary.BigEndian, sessionMsg.Timestamp)
	
	signature, err := sm.SignMessage(signData.Bytes())
	if err != nil {
		return fmt.Errorf("签名会话消息失败: %v", err)
	}
	sessionMsg.Signature = signature
	
	// 保存会话密钥
	sm.mutex.Lock()
	sm.sessionKeys[remoteNodeID] = sessionKey
	sm.sessionKeyTimestamps[remoteNodeID] = time.Now()
	sm.mutex.Unlock()
	
	// 将会话消息发送给远程节点（需要通过网络层发送，此处不实现）
	// 实际应用中需要通过某种通信通道将sessionMsg发送给remoteNodeID
	
	return nil
}

// SessionEstablishMessage 会话建立消息结构
type SessionEstablishMessage struct {
	SenderID            string // 发送者ID
	ReceiverID          string // 接收者ID
	EncryptedSessionKey []byte // 加密的会话密钥
	Timestamp           int64  // 时间戳
	Signature           []byte // 签名
}

// HandleSessionEstablish 处理收到的会话建立请求
func (sm *P2PSecurityManager) HandleSessionEstablish(sessionMsg *SessionEstablishMessage) error {
	// 验证消息是否是发给本地节点的
	if sessionMsg.ReceiverID != sm.localNodeID {
		return fmt.Errorf("会话消息不是发给本地节点的")
	}
	
	// 验证发送方是否是可信节点
	if !sm.IsNodeTrusted(sessionMsg.SenderID) {
		return fmt.Errorf("会话请求来自不受信任的节点: %s", sessionMsg.SenderID)
	}
	
	// 验证消息签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(sessionMsg.SenderID))
	signData.Write([]byte(sessionMsg.ReceiverID))
	signData.Write(sessionMsg.EncryptedSessionKey)
	binary.Write(signData, binary.BigEndian, sessionMsg.Timestamp)
	
	senderPubKey, exists := sm.trustedNodes[sessionMsg.SenderID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", sessionMsg.SenderID)
	}
	
	err := sm.VerifySignature(signData.Bytes(), sessionMsg.Signature, senderPubKey)
	if err != nil {
		return fmt.Errorf("会话消息签名验证失败: %v", err)
	}
	
	// 防重放攻击检查
	now := time.Now()
	msgTime := time.Unix(0, sessionMsg.Timestamp)
	if now.Sub(msgTime) > 5*time.Minute {
		return fmt.Errorf("会话消息过期")
	}
	
	// 使用本地私钥解密会话密钥
	sessionKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		sm.privateKey,
		sessionMsg.EncryptedSessionKey,
		[]byte("session-key"),
	)
	if err != nil {
		return fmt.Errorf("解密会话密钥失败: %v", err)
	}
	
	// 保存会话密钥
	sm.mutex.Lock()
	sm.sessionKeys[sessionMsg.SenderID] = sessionKey
	sm.sessionKeyTimestamps[sessionMsg.SenderID] = time.Now()
	sm.mutex.Unlock()
	
	return nil
}

// RefreshSession 刷新会话密钥
func (sm *P2PSecurityManager) RefreshSession(nodeID string) error {
	// 检查节点是否可信
	if !sm.IsNodeTrusted(nodeID) {
		return fmt.Errorf("节点 %s 不可信，无法刷新会话", nodeID)
	}
	
	// 获取节点的公钥
	remotePubKey, exists := sm.trustedNodes[nodeID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", nodeID)
	}
	
	// 重新建立会话
	return sm.EstablishSession(nodeID, remotePubKey)
}

// CloseSession 关闭与节点的会话
func (sm *P2PSecurityManager) CloseSession(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyTimestamps, nodeID)
}

// GetSessionsStatus 获取所有会话的状态信息
func (sm *P2PSecurityManager) GetSessionsStatus() map[string]SessionStatus {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	status := make(map[string]SessionStatus)
	now := time.Now()
	
	for nodeID, timestamp := range sm.sessionKeyTimestamps {
		_, keyExists := sm.sessionKeys[nodeID]
		duration := now.Sub(timestamp)
		
		status[nodeID] = SessionStatus{
			Active:    keyExists,
			Duration:  duration,
			ValidDays: (24*time.Hour - duration) / (24 * time.Hour),
		}
	}
	
	return status
}

// SessionStatus 会话状态信息
type SessionStatus struct {
	Active    bool          // 会话是否激活
	Duration  time.Duration // 会话持续时间
	ValidDays float64       // 会话剩余有效天数
}

// RotateSessionKey 轮换指定节点的会话密钥
func (sm *P2PSecurityManager) RotateSessionKey(nodeID string) error {
	// 检查节点是否可信
	if !sm.IsNodeTrusted(nodeID) {
		return fmt.Errorf("节点 %s 不可信，无法轮换会话密钥", nodeID)
	}
	
	// 获取节点的公钥
	remotePubKey, exists := sm.trustedNodes[nodeID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", nodeID)
	}
	
	// 转换为rsa.PublicKey类型
	pubKey, err := x509.ParsePKCS1PublicKey(remotePubKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	// 生成新的会话密钥
	newSessionKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(newSessionKey); err != nil {
		return fmt.Errorf("生成新会话密钥失败: %v", err)
	}
	
	// 创建密钥轮换消息
	rotationMsg := &KeyRotationMessage{
		SenderID:              sm.localNodeID,
		ReceiverID:            nodeID,
		EncryptedNewSessionKey: nil, // 下面会设置
		Timestamp:             time.Now().UnixNano(),
		RotationID:            sm.generateRotationID(),
	}
	
	// 使用对方的公钥加密新的会话密钥
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		newSessionKey,
		[]byte("key-rotation"),
	)
	if err != nil {
		return fmt.Errorf("加密新会话密钥失败: %v", err)
	}
	rotationMsg.EncryptedNewSessionKey = encryptedKey
	
	// 签名密钥轮换消息
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(rotationMsg.SenderID))
	signData.Write([]byte(rotationMsg.ReceiverID))
	signData.Write(rotationMsg.EncryptedNewSessionKey)
	binary.Write(signData, binary.BigEndian, rotationMsg.Timestamp)
	signData.Write([]byte(rotationMsg.RotationID))
	
	signature, err := sm.SignMessage(signData.Bytes())
	if err != nil {
		return fmt.Errorf("签名密钥轮换消息失败: %v", err)
	}
	rotationMsg.Signature = signature
	
	// 保存新的会话密钥（在收到确认前暂不替换旧密钥）
	sm.mutex.Lock()
	sm.pendingKeyRotations[nodeID] = &PendingKeyRotation{
		NewSessionKey: newSessionKey,
		RotationID:    rotationMsg.RotationID,
		InitiatedAt:   time.Now(),
	}
	sm.mutex.Unlock()
	
	// 将密钥轮换消息发送给远程节点（需要通过网络层发送，此处不实现）
	// 实际应用中需要通过某种通信通道将rotationMsg发送给nodeID
	
	return nil
}

// KeyRotationMessage 密钥轮换消息结构
type KeyRotationMessage struct {
	SenderID               string // 发送者ID
	ReceiverID             string // 接收者ID
	EncryptedNewSessionKey []byte // 加密的新会话密钥
	Timestamp              int64  // 时间戳
	RotationID             string // 轮换ID
	Signature              []byte // 签名
}

// PendingKeyRotation 等待确认的密钥轮换
type PendingKeyRotation struct {
	NewSessionKey []byte    // 新的会话密钥
	RotationID    string    // 轮换ID
	InitiatedAt   time.Time // 发起时间
}

// generateRotationID 生成密钥轮换ID
func (sm *P2PSecurityManager) generateRotationID() string {
	// 生成随机ID
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return fmt.Sprintf("%x", randomBytes)
}

// HandleKeyRotation 处理收到的密钥轮换请求
func (sm *P2PSecurityManager) HandleKeyRotation(rotationMsg *KeyRotationMessage) error {
	// 验证消息是否是发给本地节点的
	if rotationMsg.ReceiverID != sm.localNodeID {
		return fmt.Errorf("密钥轮换消息不是发给本地节点的")
	}
	
	// 验证发送方是否是可信节点
	if !sm.IsNodeTrusted(rotationMsg.SenderID) {
		return fmt.Errorf("密钥轮换请求来自不受信任的节点: %s", rotationMsg.SenderID)
	}
	
	// 验证消息签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(rotationMsg.SenderID))
	signData.Write([]byte(rotationMsg.ReceiverID))
	signData.Write(rotationMsg.EncryptedNewSessionKey)
	binary.Write(signData, binary.BigEndian, rotationMsg.Timestamp)
	signData.Write([]byte(rotationMsg.RotationID))
	
	senderPubKey, exists := sm.trustedNodes[rotationMsg.SenderID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", rotationMsg.SenderID)
	}
	
	// 转换为rsa.PublicKey
	pubKey, err := x509.ParsePKCS1PublicKey(senderPubKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	err = sm.VerifySignature(signData.Bytes(), rotationMsg.Signature, pubKey)
	if err != nil {
		return fmt.Errorf("密钥轮换消息签名验证失败: %v", err)
	}
	
	// 防重放攻击检查
	now := time.Now()
	msgTime := time.Unix(0, rotationMsg.Timestamp)
	if now.Sub(msgTime) > 5*time.Minute {
		return fmt.Errorf("密钥轮换消息过期")
	}
	
	// 使用本地私钥解密新会话密钥
	newSessionKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		sm.privateKey,
		rotationMsg.EncryptedNewSessionKey,
		[]byte("key-rotation"),
	)
	if err != nil {
		return fmt.Errorf("解密新会话密钥失败: %v", err)
	}
	
	// 保存新的会话密钥
	sm.mutex.Lock()
	sm.sessionKeys[rotationMsg.SenderID] = newSessionKey
	sm.sessionKeyTimestamps[rotationMsg.SenderID] = time.Now()
	sm.mutex.Unlock()
	
	// 创建并发送密钥轮换确认消息
	confirmMsg := &KeyRotationConfirmMessage{
		SenderID:    sm.localNodeID,
		ReceiverID:  rotationMsg.SenderID,
		RotationID:  rotationMsg.RotationID,
		Timestamp:   time.Now().UnixNano(),
	}
	
	// 签名确认消息
	confirmSignData := bytes.NewBuffer(nil)
	confirmSignData.Write([]byte(confirmMsg.SenderID))
	confirmSignData.Write([]byte(confirmMsg.ReceiverID))
	confirmSignData.Write([]byte(confirmMsg.RotationID))
	binary.Write(confirmSignData, binary.BigEndian, confirmMsg.Timestamp)
	
	confirmSignature, err := sm.SignMessage(confirmSignData.Bytes())
	if err != nil {
		return fmt.Errorf("签名确认消息失败: %v", err)
	}
	confirmMsg.Signature = confirmSignature
	
	// 将确认消息发送给远程节点（需要通过网络层发送，此处不实现）
	// 实际应用中需要通过某种通信通道将confirmMsg发送给rotationMsg.SenderID
	
	return nil
}

// KeyRotationConfirmMessage 密钥轮换确认消息结构
type KeyRotationConfirmMessage struct {
	SenderID    string // 发送者ID
	ReceiverID  string // 接收者ID
	RotationID  string // 轮换ID
	Timestamp   int64  // 时间戳
	Signature   []byte // 签名
}

// HandleKeyRotationConfirm 处理密钥轮换确认消息
func (sm *P2PSecurityManager) HandleKeyRotationConfirm(confirmMsg *KeyRotationConfirmMessage) error {
	// 验证消息是否是发给本地节点的
	if confirmMsg.ReceiverID != sm.localNodeID {
		return fmt.Errorf("密钥轮换确认消息不是发给本地节点的")
	}
	
	// 验证发送方是否是可信节点
	if !sm.IsNodeTrusted(confirmMsg.SenderID) {
		return fmt.Errorf("密钥轮换确认来自不受信任的节点: %s", confirmMsg.SenderID)
	}
	
	// 验证消息签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(confirmMsg.SenderID))
	signData.Write([]byte(confirmMsg.ReceiverID))
	signData.Write([]byte(confirmMsg.RotationID))
	binary.Write(signData, binary.BigEndian, confirmMsg.Timestamp)
	
	senderPubKey, exists := sm.trustedNodes[confirmMsg.SenderID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", confirmMsg.SenderID)
	}
	
	// 转换为rsa.PublicKey
	pubKey, err := x509.ParsePKCS1PublicKey(senderPubKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	err = sm.VerifySignature(signData.Bytes(), confirmMsg.Signature, pubKey)
	if err != nil {
		return fmt.Errorf("密钥轮换确认消息签名验证失败: %v", err)
	}
	
	// 查找对应的等待确认密钥轮换
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	pendingRotation, exists := sm.pendingKeyRotations[confirmMsg.SenderID]
	if !exists {
		return fmt.Errorf("没有找到与节点 %s 的待确认密钥轮换", confirmMsg.SenderID)
	}
	
	// 验证轮换ID是否匹配
	if pendingRotation.RotationID != confirmMsg.RotationID {
		return fmt.Errorf("密钥轮换ID不匹配")
	}
	
	// 应用新的会话密钥
	sm.sessionKeys[confirmMsg.SenderID] = pendingRotation.NewSessionKey
	sm.sessionKeyTimestamps[confirmMsg.SenderID] = time.Now()
	
	// 删除待确认的密钥轮换
	delete(sm.pendingKeyRotations, confirmMsg.SenderID)
	
	return nil
}

// ScheduleKeyRotation 安排定期密钥轮换
func (sm *P2PSecurityManager) ScheduleKeyRotation(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for range ticker.C {
			sm.rotateAllSessionKeys()
		}
	}()
}

// rotateAllSessionKeys 轮换所有会话密钥
func (sm *P2PSecurityManager) rotateAllSessionKeys() {
	sm.mutex.RLock()
	nodeIDs := make([]string, 0, len(sm.sessionKeys))
	for nodeID := range sm.sessionKeys {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sm.mutex.RUnlock()
	
	for _, nodeID := range nodeIDs {
		// 为每个节点发起密钥轮换
		err := sm.RotateSessionKey(nodeID)
		if err != nil {
			// 记录错误，但继续处理其他节点
			fmt.Printf("轮换节点 %s 的会话密钥失败: %v\n", nodeID, err)
		}
	}
}

// ConnectionStatus 连接状态
type ConnectionStatus int

const (
	ConnectionDisconnected ConnectionStatus = iota // 断开连接
	ConnectionPending                              // 连接挂起
	ConnectionEstablished                          // 连接已建立
	ConnectionAuthenticated                        // 连接已认证
	ConnectionEncrypted                            // 连接已加密
	ConnectionSecure                               // 连接安全（已认证且已加密）
)

// 连接信息
type ConnectionInfo struct {
	Status            ConnectionStatus // 连接状态
	EstablishedAt     time.Time        // 连接建立时间
	LastActivityAt    time.Time        // 最后活动时间
	BytesSent         int64            // 已发送字节数
	BytesReceived     int64            // 已接收字节数
	MessagesSent      int64            // 已发送消息数
	MessagesReceived  int64            // 已接收消息数
	Errors            int              // 错误计数
	FailedAttempts    int              // 失败尝试计数
	IsAuthenticated   bool             // 是否已认证
	IsEncrypted       bool             // 是否已加密
}

// UpdateConnectionStatus 更新节点连接状态
func (sm *P2PSecurityManager) UpdateConnectionStatus(nodeID string, status ConnectionStatus) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	info, exists := sm.connectionInfo[nodeID]
	if !exists {
		info = &ConnectionInfo{
			EstablishedAt:  time.Now(),
			LastActivityAt: time.Now(),
		}
		sm.connectionInfo[nodeID] = info
	}
	
	// 更新状态和最后活动时间
	info.Status = status
	info.LastActivityAt = time.Now()
	
	// 根据状态更新认证和加密标志
	if status == ConnectionAuthenticated || status == ConnectionSecure {
		info.IsAuthenticated = true
	}
	
	if status == ConnectionEncrypted || status == ConnectionSecure {
		info.IsEncrypted = true
	}
}

// GetConnectionStatus 获取节点的连接状态
func (sm *P2PSecurityManager) GetConnectionStatus(nodeID string) *ConnectionInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	info, exists := sm.connectionInfo[nodeID]
	if !exists {
		return &ConnectionInfo{
			Status: ConnectionDisconnected,
		}
	}
	
	return info
}

// UpdateConnectionStats 更新连接统计信息
func (sm *P2PSecurityManager) UpdateConnectionStats(nodeID string, bytesSent, bytesReceived int, messagesSent, messagesReceived int) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	info, exists := sm.connectionInfo[nodeID]
	if !exists {
		info = &ConnectionInfo{
			EstablishedAt:  time.Now(),
			LastActivityAt: time.Now(),
		}
		sm.connectionInfo[nodeID] = info
	}
	
	// 更新统计信息
	info.BytesSent += int64(bytesSent)
	info.BytesReceived += int64(bytesReceived)
	info.MessagesSent += int64(messagesSent)
	info.MessagesReceived += int64(messagesReceived)
	info.LastActivityAt = time.Now()
}

// RecordConnectionError 记录连接错误
func (sm *P2PSecurityManager) RecordConnectionError(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	info, exists := sm.connectionInfo[nodeID]
	if !exists {
		info = &ConnectionInfo{
			EstablishedAt:  time.Now(),
			LastActivityAt: time.Now(),
		}
		sm.connectionInfo[nodeID] = info
	}
	
	// 增加错误计数
	info.Errors++
	info.LastActivityAt = time.Now()
}

// CleanupInactiveConnections 清理不活跃连接
func (sm *P2PSecurityManager) CleanupInactiveConnections(timeout time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now()
	
	for nodeID, info := range sm.connectionInfo {
		// 如果连接长时间不活跃，清理相关资源
		if now.Sub(info.LastActivityAt) > timeout {
			// 删除会话密钥
			delete(sm.sessionKeys, nodeID)
			delete(sm.sessionKeyTimestamps, nodeID)
			delete(sm.connectionInfo, nodeID)
			
			// 如果有待确认的密钥轮换，也一并删除
			delete(sm.pendingKeyRotations, nodeID)
		}
	}
}

// TrustLevel 节点信任级别
type TrustLevel int

const (
	TrustLevelUnknown   TrustLevel = iota // 未知节点
	TrustLevelSuspicious                   // 可疑节点
	TrustLevelBasic                        // 基本信任
	TrustLevelVerified                     // 已验证节点
	TrustLevelTrusted                      // 受信任节点
	TrustLevelHighTrust                    // 高度信任
)

// NodeTrustInfo 节点信任信息
type NodeTrustInfo struct {
	TrustLevel       TrustLevel // 信任级别
	FirstSeen        time.Time  // 首次见到时间
	LastVerified     time.Time  // 最后验证时间
	VerificationCount int        // 验证次数
	PublicKey        []byte     // 节点公钥
	SecurityScore    float64    // 安全评分
	Blacklisted      bool       // 是否黑名单
	BlacklistReason  string     // 黑名单原因
	TrustHistory     []TrustEvent // 信任历史事件
}

// TrustEvent 信任历史事件
type TrustEvent struct {
	Timestamp    time.Time  // 事件时间
	EventType    string     // 事件类型
	TrustChange  int        // 信任变化（正数表示增加，负数表示减少）
	Description  string     // 事件描述
}

// AddTrustedNode 添加受信任节点
func (sm *P2PSecurityManager) AddTrustedNode(nodeID string, publicKey []byte, trustLevel TrustLevel) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 保存公钥到信任节点映射表
	sm.trustedNodes[nodeID] = publicKey
	
	// 创建或更新节点信任信息
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if !exists {
		trustInfo = &NodeTrustInfo{
			FirstSeen:    time.Now(),
			LastVerified: time.Now(),
			PublicKey:    publicKey,
			TrustHistory: make([]TrustEvent, 0),
		}
		sm.nodeTrustInfo[nodeID] = trustInfo
	}
	
	// 记录信任事件
	trustInfo.TrustLevel = trustLevel
	trustInfo.LastVerified = time.Now()
	trustInfo.VerificationCount++
	
	trustInfo.TrustHistory = append(trustInfo.TrustHistory, TrustEvent{
		Timestamp:   time.Now(),
		EventType:   "添加信任",
		TrustChange: int(trustLevel),
		Description: fmt.Sprintf("节点添加为信任节点，信任级别: %d", trustLevel),
	})
	
	// 计算安全评分
	sm.calculateSecurityScore(nodeID)
}

// RemoveTrustedNode 移除信任节点
func (sm *P2PSecurityManager) RemoveTrustedNode(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 从信任节点映射表中删除
	delete(sm.trustedNodes, nodeID)
	
	// 更新节点信任信息
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if exists {
		trustInfo.TrustLevel = TrustLevelUnknown
		
		trustInfo.TrustHistory = append(trustInfo.TrustHistory, TrustEvent{
			Timestamp:   time.Now(),
			EventType:   "移除信任",
			TrustChange: -int(TrustLevelTrusted),
			Description: "节点从信任列表中移除",
		})
	}
	
	// 清理相关会话数据
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyTimestamps, nodeID)
	delete(sm.pendingKeyRotations, nodeID)
}

// BlacklistNode 将节点加入黑名单
func (sm *P2PSecurityManager) BlacklistNode(nodeID string, reason string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 从信任节点映射表中删除
	delete(sm.trustedNodes, nodeID)
	
	// 更新节点信任信息
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if !exists {
		trustInfo = &NodeTrustInfo{
			FirstSeen:    time.Now(),
			TrustHistory: make([]TrustEvent, 0),
		}
		sm.nodeTrustInfo[nodeID] = trustInfo
	}
	
	trustInfo.TrustLevel = TrustLevelSuspicious
	trustInfo.Blacklisted = true
	trustInfo.BlacklistReason = reason
	
	trustInfo.TrustHistory = append(trustInfo.TrustHistory, TrustEvent{
		Timestamp:   time.Now(),
		EventType:   "黑名单",
		TrustChange: -100,
		Description: fmt.Sprintf("节点已加入黑名单，原因: %s", reason),
	})
	
	// 清理相关会话数据
	delete(sm.sessionKeys, nodeID)
	delete(sm.sessionKeyTimestamps, nodeID)
	delete(sm.pendingKeyRotations, nodeID)
}

// UnblacklistNode 将节点从黑名单中移除
func (sm *P2PSecurityManager) UnblacklistNode(nodeID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if exists && trustInfo.Blacklisted {
		trustInfo.Blacklisted = false
		trustInfo.TrustLevel = TrustLevelBasic
		
		trustInfo.TrustHistory = append(trustInfo.TrustHistory, TrustEvent{
			Timestamp:   time.Now(),
			EventType:   "移除黑名单",
			TrustChange: 10,
			Description: "节点从黑名单中移除",
		})
	}
}

// IsNodeBlacklisted 检查节点是否在黑名单中
func (sm *P2PSecurityManager) IsNodeBlacklisted(nodeID string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	return exists && trustInfo.Blacklisted
}

// GetNodeTrustInfo 获取节点信任信息
func (sm *P2PSecurityManager) GetNodeTrustInfo(nodeID string) *NodeTrustInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if !exists {
		return &NodeTrustInfo{
			TrustLevel: TrustLevelUnknown,
		}
	}
	
	return trustInfo
}

// RecordTrustEvent 记录信任事件
func (sm *P2PSecurityManager) RecordTrustEvent(nodeID string, eventType string, trustChange int, description string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if !exists {
		trustInfo = &NodeTrustInfo{
			FirstSeen:    time.Now(),
			TrustLevel:   TrustLevelUnknown,
			TrustHistory: make([]TrustEvent, 0),
		}
		sm.nodeTrustInfo[nodeID] = trustInfo
	}
	
	// 添加事件
	trustInfo.TrustHistory = append(trustInfo.TrustHistory, TrustEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		TrustChange: trustChange,
		Description: description,
	})
	
	// 重新计算安全评分
	sm.calculateSecurityScore(nodeID)
}

// calculateSecurityScore 计算节点安全评分
func (sm *P2PSecurityManager) calculateSecurityScore(nodeID string) {
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if !exists {
		return
	}
	
	var score float64 = 50 // 基础分
	
	// 根据信任级别加分
	score += float64(trustInfo.TrustLevel) * 10
	
	// 验证次数加分
	score += math.Min(float64(trustInfo.VerificationCount), 10) * 2
	
	// 根据历史事件调整分数
	for _, event := range trustInfo.TrustHistory {
		// 只考虑最近30天的事件
		if time.Since(event.Timestamp) <= 30*24*time.Hour {
			score += float64(event.TrustChange)
		}
	}
	
	// 黑名单节点分数为0
	if trustInfo.Blacklisted {
		score = 0
	}
	
	// 限制分数范围
	score = math.Max(0, math.Min(100, score))
	
	trustInfo.SecurityScore = score
}

// VerifyNodeIdentity 验证节点身份
func (sm *P2PSecurityManager) VerifyNodeIdentity(nodeID string, challenge []byte, signature []byte) error {
	sm.mutex.RLock()
	pubKey, exists := sm.trustedNodes[nodeID]
	sm.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("节点 %s 不是信任节点", nodeID)
	}
	
	// 转换为rsa.PublicKey
	rsaPubKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	// 验证签名
	err = sm.VerifySignature(challenge, signature, rsaPubKey)
	if err != nil {
		// 记录失败事件
		sm.RecordTrustEvent(nodeID, "身份验证失败", -5, fmt.Sprintf("验证失败原因: %v", err))
		return fmt.Errorf("身份验证失败: %v", err)
	}
	
	// 验证成功，增加信任度
	sm.mutex.Lock()
	trustInfo, exists := sm.nodeTrustInfo[nodeID]
	if exists {
		trustInfo.LastVerified = time.Now()
		trustInfo.VerificationCount++
	}
	sm.mutex.Unlock()
	
	sm.RecordTrustEvent(nodeID, "身份验证成功", 2, "成功验证节点身份")
	return nil
}

// GenerateChallenge 生成身份验证挑战
func (sm *P2PSecurityManager) GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("生成挑战失败: %v", err)
	}
	return challenge, nil
}

// SignChallenge 签名挑战
func (sm *P2PSecurityManager) SignChallenge(challenge []byte) ([]byte, error) {
	return sm.SignMessage(challenge)
}

// SecureDataTransfer 安全数据传输结构
type SecureDataTransfer struct {
	TransferID      string    // 传输ID
	SenderID        string    // 发送者ID
	ReceiverID      string    // 接收者ID
	ChunkCount      int       // 总块数
	ChunkSize       int       // 块大小
	TotalSize       int64     // 总大小
	DataHash        []byte    // 数据哈希
	SecurityOptions uint32    // 安全选项位掩码
	StartTime       time.Time // 开始时间
	Timeout         time.Duration // 超时时间
}

// DataChunk 数据块结构
type DataChunk struct {
	TransferID   string // 传输ID
	ChunkIndex   int    // 块索引
	Data         []byte // 数据
	Checksum     []byte // 校验和
	Signature    []byte // 签名
}

// InitiateSecureTransfer 发起安全数据传输
func (sm *P2PSecurityManager) InitiateSecureTransfer(receiverID string, data []byte, chunkSize int) (*SecureDataTransfer, error) {
	// 检查接收者是否是信任节点
	if !sm.IsNodeTrusted(receiverID) {
		return nil, fmt.Errorf("节点 %s 不是信任节点", receiverID)
	}
	
	// 生成传输ID
	transferID := sm.generateTransferID()
	
	// 计算总块数
	totalSize := int64(len(data))
	chunkCount := (int(totalSize) + chunkSize - 1) / chunkSize
	
	// 计算数据哈希
	dataHash := sha256.Sum256(data)
	
	// 创建安全传输对象
	transfer := &SecureDataTransfer{
		TransferID:      transferID,
		SenderID:        sm.localNodeID,
		ReceiverID:      receiverID,
		ChunkCount:      chunkCount,
		ChunkSize:       chunkSize,
		TotalSize:       totalSize,
		DataHash:        dataHash[:],
		SecurityOptions: 0x01, // 默认启用签名验证
		StartTime:       time.Now(),
		Timeout:         5 * time.Minute,
	}
	
	// 将数据分块并处理
	for i := 0; i < chunkCount; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		
		chunkData := data[start:end]
		
		// 计算校验和
		checksum := sha256.Sum256(chunkData)
		
		// 创建块结构
		chunk := &DataChunk{
			TransferID: transferID,
			ChunkIndex: i,
			Data:       chunkData,
			Checksum:   checksum[:],
		}
		
		// 签名数据块
		signData := bytes.NewBuffer(nil)
		signData.Write([]byte(chunk.TransferID))
		binary.Write(signData, binary.BigEndian, chunk.ChunkIndex)
		signData.Write(chunk.Data)
		signData.Write(chunk.Checksum)
		
		signature, err := sm.SignMessage(signData.Bytes())
		if err != nil {
			return nil, fmt.Errorf("签名数据块失败: %v", err)
		}
		chunk.Signature = signature
		
		// 发送数据块（需要通过网络层发送，此处不实现）
		// 实际应用中需要通过某种通信通道将chunk发送给receiverID
	}
	
	return transfer, nil
}

// generateTransferID 生成传输ID
func (sm *P2PSecurityManager) generateTransferID() string {
	// 生成随机ID
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s-%x-%x", sm.localNodeID[:8], timestamp, randomBytes)
}

// VerifyDataChunk 验证数据块
func (sm *P2PSecurityManager) VerifyDataChunk(chunk *DataChunk) error {
	// 验证发送者是否是可信节点（通过从transferID提取发送者ID）
	parts := strings.Split(chunk.TransferID, "-")
	if len(parts) < 2 {
		return fmt.Errorf("无效的传输ID")
	}
	
	senderID := parts[0] + "-" + parts[1] // 假设传输ID包含发送者ID
	
	if !sm.IsNodeTrusted(senderID) {
		return fmt.Errorf("块接收自不受信任的节点: %s", senderID)
	}
	
	// 验证校验和
	computedChecksum := sha256.Sum256(chunk.Data)
	if !bytes.Equal(computedChecksum[:], chunk.Checksum) {
		return fmt.Errorf("校验和不匹配")
	}
	
	// 验证签名
	signData := bytes.NewBuffer(nil)
	signData.Write([]byte(chunk.TransferID))
	binary.Write(signData, binary.BigEndian, chunk.ChunkIndex)
	signData.Write(chunk.Data)
	signData.Write(chunk.Checksum)
	
	senderPubKey, exists := sm.trustedNodes[senderID]
	if !exists {
		return fmt.Errorf("无法获取节点 %s 的公钥", senderID)
	}
	
	// 转换为rsa.PublicKey
	pubKey, err := x509.ParsePKCS1PublicKey(senderPubKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}
	
	err = sm.VerifySignature(signData.Bytes(), chunk.Signature, pubKey)
	if err != nil {
		return fmt.Errorf("数据块签名验证失败: %v", err)
	}
	
	return nil
}

// SendSecureMessage 发送安全消息
func (sm *P2PSecurityManager) SendSecureMessage(receiverID string, messageType uint8, payload []byte) error {
	// 创建安全消息
	msg, err := sm.CreateSecureMessage(receiverID, payload)
	if err != nil {
		return fmt.Errorf("创建安全消息失败: %v", err)
	}
	
	// 加密负载
	encryptedPayload, err := sm.EncryptPayload(receiverID, payload)
	if err != nil {
		return fmt.Errorf("加密负载失败: %v", err)
	}
	
	// 更新消息头部和负载
	msg.Header.PayloadLen = uint32(len(encryptedPayload))
	msg.EncryptedPayload = encryptedPayload
	
	// 序列化消息
	serializedMsg, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}
	
	// 更新连接统计信息
	sm.UpdateConnectionStats(receiverID, len(serializedMsg), 0, 1, 0)
	
	// 发送消息（需要通过网络层发送，此处不实现）
	// 实际应用中需要通过某种通信通道将serializedMsg发送给receiverID
	
	return nil
}

// ReceiveSecureMessage 接收安全消息
func (sm *P2PSecurityManager) ReceiveSecureMessage(messageData []byte) (string, []byte, error) {
	// 反序列化消息
	msg, err := DeserializeSecureMessage(messageData)
	if err != nil {
		return "", nil, fmt.Errorf("反序列化消息失败: %v", err)
	}
	
	// 解密和验证消息
	payload, err := sm.VerifyAndUnpackMessage(msg)
	if err != nil {
		return "", nil, fmt.Errorf("验证消息失败: %v", err)
	}
	
	// 更新连接统计信息
	sm.UpdateConnectionStats(msg.Header.SenderID, 0, len(messageData), 0, 1)
	
	return msg.Header.SenderID, payload, nil
}

// ExportedAPI 为外部应用提供的公开API
type P2PSecurityAPI struct {
	manager *P2PSecurityManager
}

// NewP2PSecurityAPI 创建新的安全API实例
func NewP2PSecurityAPI(nodeID string, privateKey, publicKey []byte) (*P2PSecurityAPI, error) {
	// 创建默认安全配置
	config := &SecurityConfig{
		SessionKeyLength:  32,    // 32字节（256位）的会话密钥
		SessionKeyTTL:     86400, // 会话密钥24小时有效
		MessageTTL:        300,   // 消息5分钟有效
		MaxClockSkew:      60,    // 最大时钟偏差1分钟
		NonceLength:       16,    // 16字节随机数
		MaxMessageHistory: 1000,  // 最多保存1000条消息历史
	}
	
	// 创建安全管理器
	manager := NewP2PSecurityManager(nodeID, privateKey, publicKey, config)
	
	// 启动定期任务
	go func() {
		// 每小时检查一次过期的会话密钥
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		
		for {
			<-ticker.C
			manager.refreshExpiredSessionKeys()
			manager.cleanupOldMessages()
		}
	}()
	
	// 每24小时轮换一次密钥
	manager.ScheduleKeyRotation(24 * time.Hour)
	
	return &P2PSecurityAPI{
		manager: manager,
	}, nil
}

// SetNetworkSender 设置网络发送函数
func (api *P2PSecurityAPI) SetNetworkSender(sender func(receiverID string, data []byte) error) {
	api.manager.SetNetworkSender(sender)
}

// SendSecureMessageWithRetry 发送安全消息（支持重试）
func (api *P2PSecurityAPI) SendSecureMessageWithRetry(
	receiverID string, 
	messageType uint8, 
	payload []byte, 
	priority int,
	callbackRef string) (string, error) {
	
	// 转换优先级
	msgPriority := MessagePriority(priority)
	if priority < 0 || priority > 3 {
		msgPriority = PriorityNormal
	}
	
	return api.manager.SendSecureMessageWithRetry(receiverID, messageType, payload, msgPriority, callbackRef)
}

// ReceiveAndAcknowledgeMessage 接收并确认消息
func (api *P2PSecurityAPI) ReceiveAndAcknowledgeMessage(
	messageData []byte) (string, []byte, string, error) {
	
	// 使用安全管理器处理接收到的消息
	return api.manager.ReceiveAndAcknowledgeMessage(messageData)
}

// BatchSendSecureMessages 批量发送安全消息
func (api *P2PSecurityAPI) BatchSendSecureMessages(
	receivers []string, 
	messageType uint8, 
	payload []byte, 
	priority int) map[string]string {
	
	return api.manager.BatchSendSecureMessages(
		receivers, 
		messageType, 
		payload, 
		priority)
}

// 消息安全API

// EncryptMessage 加密消息
func (api *P2PSecurityAPI) EncryptMessage(peerID string, message []byte) ([]byte, error) {
	return api.manager.EncryptPayload(peerID, message)
}

// DecryptMessage 解密消息
func (api *P2PSecurityAPI) DecryptMessage(peerID string, encryptedMessage []byte) ([]byte, error) {
	return api.manager.DecryptPayload(peerID, encryptedMessage)
}

// CreateSecureMessage 创建安全消息
func (api *P2PSecurityAPI) CreateSecureMessage(peerID string, messageType uint8, payload []byte) ([]byte, error) {
	// 创建安全消息
	secMsg, err := api.manager.CreateSecureMessage(peerID, payload)
	if err != nil {
		return nil, err
	}
	
	// 序列化消息
	return secMsg.Serialize()
}

// VerifyAndDecryptMessage 验证并解密消息
func (api *P2PSecurityAPI) VerifyAndDecryptMessage(encryptedMessage []byte) (string, []byte, error) {
	return api.manager.ReceiveSecureMessage(encryptedMessage)
}

// SignData 签名数据
func (api *P2PSecurityAPI) SignData(data []byte) ([]byte, error) {
	return api.manager.SignMessage(data)
}

// VerifySignature 验证签名
func (api *P2PSecurityAPI) VerifySignature(peerID string, data []byte, signature []byte) bool {
	// 获取节点公钥
	pubKey, exists := api.manager.trustedNodes[peerID]
	if !exists {
		return false
	}
	
	// 转换为RSA公钥
	rsaPubKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return false
	}
	
	// 验证签名
	err = api.manager.VerifySignature(data, signature, rsaPubKey)
	return err == nil
}

// CheckMessageReplay 检查消息重放
func (api *P2PSecurityAPI) CheckMessageReplay(peerID string, messageID string) bool {
	return api.manager.AddMessageToHistory(peerID, messageID)
}

// GenerateChallenge 生成验证挑战
func (api *P2PSecurityAPI) GenerateChallenge() ([]byte, error) {
	return api.manager.GenerateChallenge()
}

// ConnectionAPI 连接状态API

// UpdatePeerConnectionStatus 更新节点连接状态
func (api *P2PSecurityAPI) UpdatePeerConnectionStatus(peerID string, status int) {
	api.manager.UpdateConnectionStatus(peerID, ConnectionStatus(status))
}

// GetPeerConnectionStatus 获取节点连接状态
func (api *P2PSecurityAPI) GetPeerConnectionStatus(peerID string) *ConnectionInfo {
	return api.manager.GetConnectionStatus(peerID)
}

// RecordConnectionError 记录连接错误
func (api *P2PSecurityAPI) RecordConnectionError(peerID string) {
	api.manager.RecordConnectionError(peerID)
}

// DataTransferAPI 数据传输API

// InitiateSecureTransfer 发起安全数据传输
func (api *P2PSecurityAPI) InitiateSecureTransfer(peerID string, data []byte, chunkSize int) (string, error) {
	transfer, err := api.manager.InitiateSecureTransfer(peerID, data, chunkSize)
	if err != nil {
		return "", err
	}
	return transfer.TransferID, nil
}

// VerifyDataChunk 验证数据块
func (api *P2PSecurityAPI) VerifyDataChunk(chunk []byte) error {
	// 从字节数组反序列化为DataChunk
	// 实际实现应根据你的序列化格式来解析
	// 此处仅为示例代码
	if len(chunk) < 20 {
		return fmt.Errorf("数据块过小")
	}
	
	// 创建数据块结构并填充数据
	// 实际应用需要根据具体的序列化方式来反序列化
	dataChunk := &DataChunk{
		// 从字节数组中解析数据块信息
	}
	
	return api.manager.VerifyDataChunk(dataChunk)
}

// GetMessageDeliveryStatus 获取消息传递状态
func (api *P2PSecurityAPI) GetMessageDeliveryStatus(messageID string) int {
	// 这里需要从消息队列中获取状态
	// 由于我们没有直接从MessageQueue结构导出方法
	// 实际应用中需要添加相应的方法
	return 0 // 临时返回0
}

// MessagePriority 消息优先级
type MessagePriority int

const (
	PriorityLow    MessagePriority = 0 // 低优先级
	PriorityNormal MessagePriority = 1 // 正常优先级
	PriorityHigh   MessagePriority = 2 // 高优先级
	PriorityCritical MessagePriority = 3 // 关键优先级
)

// MessageDeliveryState 消息传递状态
type MessageDeliveryState int

const (
	DeliveryPending   MessageDeliveryState = 0 // 等待发送
	DeliverySent      MessageDeliveryState = 1 // 已发送
	DeliveryConfirmed MessageDeliveryState = 2 // 已确认
	DeliveryFailed    MessageDeliveryState = 3 // 发送失败
)

// QueuedMessage 队列中的消息
type QueuedMessage struct {
	MessageID   string            // 消息ID
	ReceiverID  string            // 接收者ID
	Content     []byte            // 消息内容
	Priority    MessagePriority   // 优先级
	Status      MessageDeliveryState // 状态
	RetryCount  int               // 重试次数
	CreatedAt   time.Time         // 创建时间
	LastTryAt   time.Time         // 最后尝试时间
	CallbackRef string            // 回调引用
}

// MessageQueue 消息队列
type MessageQueue struct {
	messages    []*QueuedMessage  // 消息列表
	mutex       sync.Mutex        // 互斥锁
	maxSize     int               // 最大队列大小
	maxRetries  int               // 最大重试次数
	retryDelay  time.Duration     // 重试延迟
}

// MessageProcessor 消息处理器
type MessageProcessor struct {
	queue           *MessageQueue  // 消息队列
	processingRate  int            // 处理速率(每秒)
	running         bool           // 是否运行中
	stopChan        chan bool      // 停止信号
	networkSender   func(receiverID string, data []byte) error // 网络发送函数
	deliveryHandlers map[string]func(messageID string, status MessageDeliveryState) // 传递处理器
	handlerMutex    sync.RWMutex   // 处理器互斥锁
	antiReplayWindow time.Duration  // 防重放窗口
	receivedMsgCache map[string]time.Time // 已接收消息缓存
	cacheMutex       sync.Mutex     // 缓存互斥锁
}

// NewMessageQueue 创建新的消息队列
func NewMessageQueue(maxSize, maxRetries int, retryDelay time.Duration) *MessageQueue {
	return &MessageQueue{
		messages:   make([]*QueuedMessage, 0),
		maxSize:    maxSize,
		maxRetries: maxRetries,
		retryDelay: retryDelay,
	}
}

// AddMessage 添加消息到队列
func (mq *MessageQueue) AddMessage(receiverID string, content []byte, priority MessagePriority, callbackRef string) string {
	mq.mutex.Lock()
	defer mq.mutex.Unlock()
	
	// 队列满时，丢弃低优先级消息
	if len(mq.messages) >= mq.maxSize {
		mq.cleanupLowPriorityMessages()
	}
	
	// 生成消息ID
	messageID := generateUniqueID()
	
	// 创建新消息
	msg := &QueuedMessage{
		MessageID:   messageID,
		ReceiverID:  receiverID,
		Content:     content,
		Priority:    priority,
		Status:      DeliveryPending,
		RetryCount:  0,
		CreatedAt:   time.Now(),
		CallbackRef: callbackRef,
	}
	
	// 按优先级插入队列
	mq.insertByPriority(msg)
	
	return messageID
}

// insertByPriority 按优先级插入消息
func (mq *MessageQueue) insertByPriority(msg *QueuedMessage) {
	// 如果队列为空，直接添加
	if len(mq.messages) == 0 {
		mq.messages = append(mq.messages, msg)
		return
	}
	
	// 按优先级插入
	for i, m := range mq.messages {
		if msg.Priority > m.Priority {
			// 插入到当前位置
			mq.messages = append(mq.messages[:i], append([]*QueuedMessage{msg}, mq.messages[i:]...)...)
			return
		}
	}
	
	// 如果没有找到更高优先级，添加到末尾
	mq.messages = append(mq.messages, msg)
}

// generateUniqueID 生成唯一ID
func generateUniqueID() string {
	// 使用时间戳和随机数生成唯一ID
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(10000))
}

// cleanupLowPriorityMessages 清理低优先级消息
func (mq *MessageQueue) cleanupLowPriorityMessages() {
	// 如果队列未满，不需要清理
	if len(mq.messages) < mq.maxSize {
		return
	}
	
	// 找出最低优先级消息并移除
	lowestPriority := PriorityCritical
	lowestIndex := -1
	
	for i, msg := range mq.messages {
		// 跳过已经发送或确认的消息
		if msg.Status == DeliverySent || msg.Status == DeliveryConfirmed {
			continue
		}
		
		if msg.Priority < lowestPriority {
			lowestPriority = msg.Priority
			lowestIndex = i
		}
	}
	
	// 如果找到低优先级消息，移除它
	if lowestIndex >= 0 {
		mq.messages = append(mq.messages[:lowestIndex], mq.messages[lowestIndex+1:]...)
	}
}

// GetNextMessage 获取下一个待发送的消息
func (mq *MessageQueue) GetNextMessage() *QueuedMessage {
	mq.mutex.Lock()
	defer mq.mutex.Unlock()
	
	currentTime := time.Now()
	
	for i, msg := range mq.messages {
		// 跳过已经确认的消息
		if msg.Status == DeliveryConfirmed {
			continue
		}
		
		// 检查重试条件：如果消息状态为失败，且重试次数未超限，且超过重试延迟
		if msg.Status == DeliveryFailed && 
		   msg.RetryCount < mq.maxRetries && 
		   currentTime.Sub(msg.LastTryAt) > mq.retryDelay {
			msg.Status = DeliveryPending
		}
		
		// 返回待发送的消息
		if msg.Status == DeliveryPending {
			// 更新状态
			mq.messages[i].Status = DeliverySent
			mq.messages[i].LastTryAt = currentTime
			return mq.messages[i]
		}
	}
	
	return nil // 没有待发送的消息
}

// UpdateMessageStatus 更新消息状态
func (mq *MessageQueue) UpdateMessageStatus(messageID string, status MessageDeliveryState) bool {
	mq.mutex.Lock()
	defer mq.mutex.Unlock()
	
	for i, msg := range mq.messages {
		if msg.MessageID == messageID {
			mq.messages[i].Status = status
			
			// 如果状态为失败，增加重试计数
			if status == DeliveryFailed {
				mq.messages[i].RetryCount++
			}
			
			return true
		}
	}
	
	return false // 消息未找到
}

// NewMessageProcessor 创建新的消息处理器
func NewMessageProcessor(queue *MessageQueue, processingRate int, networkSender func(receiverID string, data []byte) error) *MessageProcessor {
	return &MessageProcessor{
		queue:            queue,
		processingRate:   processingRate,
		running:          false,
		stopChan:         make(chan bool, 1),
		networkSender:    networkSender,
		deliveryHandlers: make(map[string]func(messageID string, status MessageDeliveryState)),
		antiReplayWindow: 5 * time.Minute, // 默认5分钟防重放窗口
		receivedMsgCache: make(map[string]time.Time),
	}
}

// Start 启动消息处理器
func (mp *MessageProcessor) Start() {
	if mp.running {
		return
	}
	
	mp.running = true
	
	// 启动消息处理循环
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(mp.processingRate))
		defer ticker.Stop()
		
		for {
			select {
			case <-mp.stopChan:
				// 收到停止信号，退出循环
				return
			case <-ticker.C:
				// 处理下一条消息
				mp.processNextMessage()
				// 清理过期缓存
				mp.cleanupCache()
			}
		}
	}()
}

// Stop 停止消息处理器
func (mp *MessageProcessor) Stop() {
	if !mp.running {
		return
	}
	
	mp.running = false
	mp.stopChan <- true
}

// processNextMessage 处理下一条消息
func (mp *MessageProcessor) processNextMessage() {
	// 获取下一条待处理消息
	msg := mp.queue.GetNextMessage()
	if msg == nil {
		return
	}
	
	// 尝试发送消息
	err := mp.networkSender(msg.ReceiverID, msg.Content)
	
	if err != nil {
		// 发送失败，更新状态
		mp.queue.UpdateMessageStatus(msg.MessageID, DeliveryFailed)
		// 通知失败
		mp.notifyHandler(msg.MessageID, DeliveryFailed)
	} else {
		// 发送成功，更新状态
		mp.queue.UpdateMessageStatus(msg.MessageID, DeliveryConfirmed)
		// 通知成功
		mp.notifyHandler(msg.MessageID, DeliveryConfirmed)
	}
}

// cleanupCache 清理过期缓存
func (mp *MessageProcessor) cleanupCache() {
	mp.cacheMutex.Lock()
	defer mp.cacheMutex.Unlock()
	
	currentTime := time.Now()
	
	// 删除过期的缓存项
	for messageID, timestamp := range mp.receivedMsgCache {
		if currentTime.Sub(timestamp) > mp.antiReplayWindow {
			delete(mp.receivedMsgCache, messageID)
		}
	}
}

// notifyHandler 通知处理函数
func (mp *MessageProcessor) notifyHandler(messageID string, status MessageDeliveryState) {
	mp.handlerMutex.RLock()
	defer mp.handlerMutex.RUnlock()
	
	// 查找并调用对应的处理函数
	if handler, ok := mp.deliveryHandlers[messageID]; ok {
		// 在新的goroutine中执行，避免阻塞消息处理
		go handler(messageID, status)
	}
}

// RegisterDeliveryHandler 注册传递处理函数
func (mp *MessageProcessor) RegisterDeliveryHandler(messageID string, handler func(messageID string, status MessageDeliveryState)) {
	mp.handlerMutex.Lock()
	defer mp.handlerMutex.Unlock()
	
	mp.deliveryHandlers[messageID] = handler
}

// UnregisterDeliveryHandler 取消注册传递处理函数
func (mp *MessageProcessor) UnregisterDeliveryHandler(messageID string) {
	mp.handlerMutex.Lock()
	defer mp.handlerMutex.Unlock()
	
	delete(mp.deliveryHandlers, messageID)
}

// CheckMessageReplay 检查消息是否重放
func (mp *MessageProcessor) CheckMessageReplay(messageID string) bool {
	mp.cacheMutex.Lock()
	defer mp.cacheMutex.Unlock()
	
	// 检查消息ID是否已存在于缓存中
	_, exists := mp.receivedMsgCache[messageID]
	
	if !exists {
		// 新消息，添加到缓存
		mp.receivedMsgCache[messageID] = time.Now()
		return false
	}
	
	// 已存在，属于重放消息
	return true
}

// SendSecureMessageWithRetry 发送安全消息并支持重试
func (sm *P2PSecurityManager) SendSecureMessageWithRetry(
	receiverID string, 
	messageType uint8, 
	payload []byte, 
	priority MessagePriority,
	callbackRef string) (string, error) {
	
	// 检查会话密钥
	if !sm.IsSessionKeyValid(receiverID) {
		// 尝试建立会话密钥
		_, err := sm.RefreshSessionKey(receiverID)
		if err != nil {
			return "", fmt.Errorf("无法建立会话密钥: %v", err)
		}
	}
	
	// 创建安全消息
	secureMsg, err := sm.EncryptAndPackMessage(receiverID, messageType, payload)
	if err != nil {
		return "", fmt.Errorf("加密消息失败: %v", err)
	}
	
	// 序列化消息
	msgData, err := secureMsg.Serialize()
	if err != nil {
		return "", fmt.Errorf("序列化消息失败: %v", err)
	}
	
	// 添加到消息队列
	messageID := sm.messageQueue.AddMessage(receiverID, msgData, priority, callbackRef)
	
	// 如果有回调，注册处理函数
	if callbackRef != "" {
		sm.deliveryMutex.Lock()
		sm.deliveryCallbacks[messageID] = func(msgID string, status MessageDeliveryState) {
			// 这里可以根据回调引用找到相应的回调函数
			// 在实际实现中，可能需要一个回调函数映射表
			// 此处简化处理
		}
		sm.deliveryMutex.Unlock()
		
		// 注册到消息处理器
		sm.messageProcessor.RegisterDeliveryHandler(messageID, func(msgID string, status MessageDeliveryState) {
			sm.deliveryMutex.RLock()
			callback, exists := sm.deliveryCallbacks[msgID]
			sm.deliveryMutex.RUnlock()
			
			if exists {
				callback(msgID, status)
			}
		})
	}
	
	return messageID, nil
}

// ReceiveAndProcessSecureMessage 接收并处理安全消息
func (sm *P2PSecurityManager) ReceiveAndProcessSecureMessage(messageData []byte) (string, []byte, error) {
	// 反序列化消息
	secureMsg, err := DeserializeSecureMessage(messageData)
	if err != nil {
		return "", nil, fmt.Errorf("反序列化消息失败: %v", err)
	}
	
	// 检查消息是否已处理（防重放）
	msgID := secureMsg.Header.MessageID
	if sm.messageProcessor.CheckMessageReplay(msgID) {
		return "", nil, fmt.Errorf("检测到重放消息: %s", msgID)
	}
	
	// 验证并解包消息
	payload, err := sm.VerifyAndUnpackMessage(secureMsg)
	if err != nil {
		return "", nil, fmt.Errorf("验证消息失败: %v", err)
	}
	
	// 更新连接状态
	sm.UpdateConnectionStatus(secureMsg.Header.SenderID, ConnectionStatusActive)
	
	// 返回发送者ID、负载和消息ID
	return secureMsg.Header.SenderID, payload, nil
}

// BatchSendSecureMessages 批量发送安全消息
func (sm *P2PSecurityManager) BatchSendSecureMessages(
	receivers []string, 
	messageType uint8, 
	payload []byte, 
	priority MessagePriority) map[string]string {
	
	results := make(map[string]string)
	
	for _, receiverID := range receivers {
		messageID, err := sm.SendSecureMessageWithRetry(receiverID, messageType, payload, priority, "")
		if err != nil {
			results[receiverID] = fmt.Sprintf("错误: %v", err)
		} else {
			results[receiverID] = messageID
		}
	}
	
	return results
}

// AntiReplayCheck 增强版防重放检查
func (sm *P2PSecurityManager) AntiReplayCheck(senderID string, sequenceNum uint64, timestamp time.Time) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now()
	
	// 检查时间窗口
	if now.Sub(timestamp) > time.Duration(sm.config.MessageTTL)*time.Second {
		return fmt.Errorf("消息过期: 消息时间戳 %v, 当前时间 %v", timestamp, now)
	}
	
	// 检查时钟偏差
	if timestamp.After(now.Add(time.Duration(sm.config.MaxClockSkew) * time.Second)) {
		return fmt.Errorf("消息时间戳超前于当前时间太多: %v", timestamp)
	}
	
	// 对每个发送者维护最后接收的序列号
	lastSequenceNum, ok := sm.sequenceNumbers[senderID]
	
	// 检查序列号
	if ok {
		// 序列号应该大于最后接收的序列号
		if sequenceNum <= lastSequenceNum {
			// 可疑的重放消息
			return fmt.Errorf("检测到重放消息: 序列号 %d <= 上次接收的序列号 %d", sequenceNum, lastSequenceNum)
		}
		
		// 检查序列号跨度（防止跳跃太大）
		if sequenceNum > lastSequenceNum+1000 {
			// 序列号跳跃太大，可疑
			return fmt.Errorf("序列号跳跃太大: %d -> %d", lastSequenceNum, sequenceNum)
		}
	}
	
	// 更新最后接收的序列号
	sm.sequenceNumbers[senderID] = sequenceNum
	
	return nil
}

// ScheduleKeyRotation 设置定期密钥轮换任务
func (sm *P2PSecurityManager) ScheduleKeyRotation(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			<-ticker.C
			sm.rotateAllSessionKeys()
		}
	}()
}

// strengthenSessionKey 增强会话密钥安全性
func (sm *P2PSecurityManager) strengthenSessionKey(sessionKey []byte) []byte {
	// 使用更强的密钥派生函数（HKDF）
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// 如果随机生成失败，使用当前时间作为备选
		binary.LittleEndian.PutUint64(salt, uint64(time.Now().UnixNano()))
	}
	
	// 使用HKDF-SHA256增强密钥
	hkdf := hkdf.New(sha256.New, sessionKey, salt, []byte("session-key-strengthen"))
	strengthenedKey := make([]byte, 32) // 256位密钥
	if _, err := io.ReadFull(hkdf, strengthenedKey); err != nil {
		// 如果HKDF失败，回退到简单的SHA256
		h := sha256.Sum256(append(sessionKey, salt...))
		copy(strengthenedKey, h[:])
	}
	
	return strengthenedKey
}

// refreshExpiredSessionKeys 刷新过期的会话密钥
func (sm *P2PSecurityManager) refreshExpiredSessionKeys() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	currentTime := time.Now()
	sessionsToRefresh := make([]string, 0)
	
	// 检查所有会话密钥
	for nodeID, creationTime := range sm.sessionKeyCreationTime {
		// 计算会话密钥年龄
		keyAge := currentTime.Sub(creationTime)
		
		// 如果密钥接近过期（超过75%的TTL），尝试刷新
		if keyAge > time.Duration(float64(sm.config.SessionKeyTTL)*0.75)*time.Second {
			sessionsToRefresh = append(sessionsToRefresh, nodeID)
		}
	}
	
	sm.mutex.Unlock() // 临时解锁，避免长时间持有锁
	
	// 刷新需要更新的会话密钥
	for _, nodeID := range sessionsToRefresh {
		sm.RefreshSessionKey(nodeID)
	}
	
	sm.mutex.Lock() // 重新加锁
}

// EncryptWithEnhancedAESGCM 使用增强的AES-GCM加密
func (sm *P2PSecurityManager) EncryptWithEnhancedAESGCM(plaintext, key []byte) ([]byte, error) {
	// 使用更强的密钥扩展
	strengthenedKey := sm.strengthenSessionKey(key)
	
	// 创建新的AES密码块
	block, err := aes.NewCipher(strengthenedKey)
	if err != nil {
		return nil, err
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// 创建随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// 用GCM加密
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	return ciphertext, nil
}

// DecryptWithEnhancedAESGCM 使用增强的AES-GCM解密
func (sm *P2PSecurityManager) DecryptWithEnhancedAESGCM(ciphertext, key []byte) ([]byte, error) {
	// 使用更强的密钥扩展
	strengthenedKey := sm.strengthenSessionKey(key)
	
	// 创建新的AES密码块
	block, err := aes.NewCipher(strengthenedKey)
	if err != nil {
		return nil, err
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// 检查密文长度
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("密文太短")
	}
	
	// 分离nonce和密文
	nonce, encryptedData := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	
	// 用GCM解密
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// ConstantTimeCompare 使用常量时间比较两个字节切片
func (sm *P2PSecurityManager) ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateEnhancedChallenge 生成增强型挑战
func (sm *P2PSecurityManager) GenerateEnhancedChallenge() ([]byte, []byte, error) {
	// 生成随机挑战
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return nil, nil, err
	}
	
	// 生成随机盐
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	
	// 添加时间戳
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	
	// 组合挑战数据
}

// AnalyzeNetworkSecurity 分析网络安全性
func (sm *P2PSecurityManager) AnalyzeNetworkSecurity() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	result := make(map[string]interface{})
	
	// 统计安全连接数量
	secureConnections := 0
	insecureConnections := 0
	
	for _, info := range sm.connectionInfo {
		if info.IsEncrypted && info.IsAuthenticated {
			secureConnections++
		} else {
			insecureConnections++
		}
	}
	
	// 计算会话密钥健康度
	sessionKeyHealth := make(map[string]float64)
	currentTime := time.Now()
	
	for nodeID, creationTime := range sm.sessionKeyCreationTime {
		// 计算密钥年龄占TTL的百分比
		keyAge := currentTime.Sub(creationTime)
		maxAge := time.Duration(sm.config.SessionKeyTTL) * time.Second
		healthPct := 100.0 - (keyAge.Seconds() / maxAge.Seconds() * 100.0)
		
		if healthPct < 0 {
			healthPct = 0
		}
		
		sessionKeyHealth[nodeID] = healthPct
	}
	
	// 统计黑名单节点数量
	blacklistedNodes := 0
	for _, info := range sm.nodeTrustInfo {
		if info.Blacklisted {
			blacklistedNodes++
		}
	}
	
	// 收集结果
	result["secureConnections"] = secureConnections
	result["insecureConnections"] = insecureConnections
	result["sessionKeyHealth"] = sessionKeyHealth
	result["blacklistedNodes"] = blacklistedNodes
	result["activeSessions"] = len(sm.sessionKeys)
	result["trustedNodes"] = len(sm.trustedNodes)
	
	return result
}

// DetectAbnormalBehavior 检测异常行为
func (sm *P2PSecurityManager) DetectAbnormalBehavior(nodeID string, messageRate int, dataVolume int64) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 获取连接信息
	connInfo, exists := sm.connectionInfo[nodeID]
	if !exists {
		return false // 无法判断
	}
	
	// 检查消息速率是否异常（比如突然暴增）
	// 这里简化为固定阈值，实际实现可能需要基于历史行为的动态阈值
	const maxMessageRate = 100 // 每秒最大消息数
	if messageRate > maxMessageRate {
		// 记录可疑行为
		sm.RecordTrustEvent(nodeID, "AbnormalMessageRate", -1, 
			fmt.Sprintf("异常消息速率: %d/s", messageRate))
		return true
	}
	
	// 检查数据量是否异常
	const maxDataVolume = 10 * 1024 * 1024 // 10MB
	if dataVolume > maxDataVolume {
		// 记录可疑行为
		sm.RecordTrustEvent(nodeID, "AbnormalDataVolume", -1,
			fmt.Sprintf("异常数据量: %d bytes", dataVolume))
		return true
	}
	
	return false
}

// SendSecureMessageWithRetry 发送带重试的安全消息
func (api *P2PSecurityAPI) SendSecureMessageWithRetry(
	receiverID string, 
	messageType uint8, 
	payload []byte, 
	priority int,
	callbackRef string) (string, error) {
	
	// 转换优先级
	msgPriority := MessagePriority(priority)
	if priority < 0 || priority > 3 {
		msgPriority = PriorityNormal
	}
	
	return api.manager.SendSecureMessageWithRetry(receiverID, messageType, payload, msgPriority, callbackRef)
}

// ReceiveAndProcessSecureMessage 接收并处理安全消息
func (api *P2PSecurityAPI) ReceiveAndProcessSecureMessage(
	messageData []byte) (string, []byte, error) {