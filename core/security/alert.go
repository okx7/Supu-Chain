// Copyright 2023 The Supur-Chain Authors
// This file is part of the Supur-Chain library.
//
// 安全告警处理器，提供多种告警通知方式

package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// 告警处理器接口实现
type AlertHandler struct {
	config     AlertConfig         // 告警配置
	senders    []AlertSender       // 告警发送器
	lastAlerts map[string]time.Time // 上次告警时间
	mu         sync.Mutex          // 互斥锁
}

// 告警发送器接口
type AlertSender interface {
	Name() string                        // 发送器名称
	Send(event *SecurityEvent) error     // 发送告警
}

// 创建新的告警处理器
func NewAlertHandler(config AlertConfig) *AlertHandler {
	handler := &AlertHandler{
		config:     config,
		senders:    make([]AlertSender, 0),
		lastAlerts: make(map[string]time.Time),
	}

	// 根据配置创建发送器
	for _, endpoint := range config.Endpoints {
		var sender AlertSender
		
		switch endpoint {
		case "log":
			sender = NewLogAlertSender()
		case "webhook":
			sender = NewWebhookAlertSender("https://your-webhook-url")
		case "email":
			sender = NewEmailAlertSender("admin@example.com")
		case "sms":
			sender = NewSMSAlertSender("+1234567890")
		case "telegram":
			sender = NewTelegramAlertSender("your-bot-token", "your-chat-id")
		default:
			log.Warn("未知的告警端点", "endpoint", endpoint)
			continue
		}
		
		handler.senders = append(handler.senders, sender)
	}
	
	return handler
}

// 添加告警发送器
func (h *AlertHandler) AddSender(sender AlertSender) {
	h.senders = append(h.senders, sender)
}

// 处理安全事件
func (h *AlertHandler) HandleEvent(event *SecurityEvent) error {
	// 判断是否启用告警
	if !h.config.Enabled {
		return nil
	}
	
	// 检查优先级
	if event.Priority < h.config.MinPriority {
		return nil
	}
	
	// 检查事件类型包含/排除列表
	if len(h.config.IncludeEventTypes) > 0 {
		included := false
		for _, t := range h.config.IncludeEventTypes {
			if t == event.Type {
				included = true
				break
			}
		}
		if !included {
			return nil
		}
	}
	
	for _, t := range h.config.ExcludeEventTypes {
		if t == event.Type {
			return nil
		}
	}
	
	// 检查告警节流
	if h.config.Throttle > 0 {
		h.mu.Lock()
		key := fmt.Sprintf("%d", event.Type)
		lastTime, exists := h.lastAlerts[key]
		now := time.Now()
		
		if exists && now.Sub(lastTime) < h.config.Throttle {
			h.mu.Unlock()
			return nil
		}
		
		h.lastAlerts[key] = now
		h.mu.Unlock()
	}
	
	// 发送告警
	var lastErr error
	for _, sender := range h.senders {
		if err := sender.Send(event); err != nil {
			log.Error("发送告警失败", "sender", sender.Name(), "error", err)
			lastErr = err
		}
	}
	
	return lastErr
}

// 日志告警发送器
type LogAlertSender struct{}

func NewLogAlertSender() *LogAlertSender {
	return &LogAlertSender{}
}

func (s *LogAlertSender) Name() string {
	return "log"
}

func (s *LogAlertSender) Send(event *SecurityEvent) error {
	log.Warn("安全告警",
		"type", event.Type,
		"priority", event.Priority,
		"description", event.Description,
		"time", event.Time)
	return nil
}

// Webhook告警发送器
type WebhookAlertSender struct {
	webhookURL string
	client     *http.Client
}

func NewWebhookAlertSender(webhookURL string) *WebhookAlertSender {
	return &WebhookAlertSender{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *WebhookAlertSender) Name() string {
	return "webhook"
}

func (s *WebhookAlertSender) Send(event *SecurityEvent) error {
	// 构建告警消息
	message := map[string]interface{}{
		"type":        event.Type,
		"priority":    event.Priority,
		"description": event.Description,
		"time":        event.Time,
		"data":        event.Data,
	}
	
	// 转换为JSON
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化告警消息失败: %v", err)
	}
	
	// 发送HTTP请求
	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("发送webhook请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook请求返回错误状态码: %d", resp.StatusCode)
	}
	
	return nil
}

// 邮件告警发送器
type EmailAlertSender struct {
	recipient string
}

func NewEmailAlertSender(recipient string) *EmailAlertSender {
	return &EmailAlertSender{
		recipient: recipient,
	}
}

func (s *EmailAlertSender) Name() string {
	return "email"
}

func (s *EmailAlertSender) Send(event *SecurityEvent) error {
	// 实际实现中，这里应该使用SMTP客户端发送邮件
	// 为简化示例，这里只记录日志
	log.Info("发送邮件告警",
		"to", s.recipient,
		"type", event.Type,
		"priority", event.Priority,
		"description", event.Description)
	
	return nil
}

// 短信告警发送器
type SMSAlertSender struct {
	phoneNumber string
}

func NewSMSAlertSender(phoneNumber string) *SMSAlertSender {
	return &SMSAlertSender{
		phoneNumber: phoneNumber,
	}
}

func (s *SMSAlertSender) Name() string {
	return "sms"
}

func (s *SMSAlertSender) Send(event *SecurityEvent) error {
	// 实际实现中，这里应该使用SMS API发送短信
	// 为简化示例，这里只记录日志
	log.Info("发送短信告警",
		"to", s.phoneNumber,
		"type", event.Type,
		"priority", event.Priority,
		"description", event.Description)
	
	return nil
}

// Telegram告警发送器
type TelegramAlertSender struct {
	botToken string
	chatID   string
	client   *http.Client
}

func NewTelegramAlertSender(botToken, chatID string) *TelegramAlertSender {
	return &TelegramAlertSender{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *TelegramAlertSender) Name() string {
	return "telegram"
}

func (s *TelegramAlertSender) Send(event *SecurityEvent) error {
	// 构建告警消息
	priorityText := map[SecurityPriority]string{
		Low:      "低",
		Medium:   "中",
		High:     "高",
		Critical: "紧急",
	}
	
	messageText := fmt.Sprintf(
		"⚠️ *安全告警* ⚠️\n"+
			"*类型*: %d\n"+
			"*优先级*: %s\n"+
			"*描述*: %s\n"+
			"*时间*: %s\n",
		event.Type,
		priorityText[event.Priority],
		event.Description,
		event.Time.Format("2006-01-02 15:04:05"),
	)
	
	// 构建请求参数
	message := map[string]interface{}{
		"chat_id":    s.chatID,
		"text":       messageText,
		"parse_mode": "Markdown",
	}
	
	// 转换为JSON
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化Telegram消息失败: %v", err)
	}
	
	// 发送HTTP请求
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.botToken)
	resp, err := s.client.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("发送Telegram请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("Telegram请求返回错误状态码: %d", resp.StatusCode)
	}
	
	return nil
} 