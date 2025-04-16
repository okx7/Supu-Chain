// Copyright 2023 The go-ethereum Authors
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

package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// SecurityLevel 定义安全日志的严重级别
type SecurityLevel int

// 定义不同的安全级别常量
const (
	SecurityInfo SecurityLevel = iota // 一般安全信息
	SecurityWarn                      // 安全警告
	SecurityError                     // 安全错误
	SecurityCritical                  // 严重安全事件
)

// SecurityEvent 表示一个安全事件
type SecurityEvent struct {
	Level     SecurityLevel  // 安全事件级别
	Time      time.Time      // 事件发生时间
	Component string         // 事件相关组件
	Message   string         // 事件描述
	Data      interface{}    // 事件详细数据
	SourceIP  string         // 源IP地址（可选）
	UserID    string         // 用户ID（可选）
}

// SecurityLogger 是专门用于记录安全事件的日志记录器
type SecurityLogger struct {
	handler      Handler     // 底层日志处理程序
	logFile      io.Writer   // 日志文件
	logDirectory string      // 日志存储目录
	rotateSize   int64       // 日志旋转大小（字节）
	currentSize  int64       // 当前日志文件大小
	rotateTime   time.Duration // 日志旋转时间
	lastRotate   time.Time   // 上次旋转时间
	enabled      bool        // 是否启用
}

// NewSecurityLogger 创建一个新的安全日志记录器
func NewSecurityLogger(logDir string, rotateSize int64, rotateTime time.Duration) (*SecurityLogger, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("无法创建安全日志目录: %v", err)
	}

	// 创建或打开日志文件
	logPath := filepath.Join(logDir, fmt.Sprintf("security_%s.log", time.Now().Format("20060102")))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("无法打开安全日志文件: %v", err)
	}

	// 获取文件大小
	stat, err := logFile.Stat()
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("无法获取日志文件状态: %v", err)
	}

	// 创建日志处理程序
	handler := StreamHandler(logFile, TerminalFormat(false))

	return &SecurityLogger{
		handler:      handler,
		logFile:      logFile,
		logDirectory: logDir,
		rotateSize:   rotateSize,
		currentSize:  stat.Size(),
		rotateTime:   rotateTime,
		lastRotate:   time.Now(),
		enabled:      true,
	}, nil
}

// LogEvent 记录一个安全事件
func (l *SecurityLogger) LogEvent(event SecurityEvent) error {
	if !l.enabled {
		return nil
	}

	// 检查是否需要旋转日志
	if err := l.checkRotate(); err != nil {
		return err
	}

	// 创建日志记录
	r := Record{
		Time: event.Time,
		Msg:  event.Message,
		Ctx:  []interface{}{},
	}

	// 根据安全级别设置日志级别
	switch event.Level {
	case SecurityInfo:
		r.Lvl = LvlInfo
	case SecurityWarn:
		r.Lvl = LvlWarn
	case SecurityError:
		r.Lvl = LvlError
	case SecurityCritical:
		r.Lvl = LvlCrit
	}

	// 添加上下文信息
	r.Ctx = append(r.Ctx, "security_level", event.Level)
	r.Ctx = append(r.Ctx, "component", event.Component)
	
	if event.SourceIP != "" {
		r.Ctx = append(r.Ctx, "source_ip", event.SourceIP)
	}
	
	if event.UserID != "" {
		r.Ctx = append(r.Ctx, "user_id", event.UserID)
	}
	
	if event.Data != nil {
		r.Ctx = append(r.Ctx, "data", event.Data)
	}

	// 记录日志
	l.handler.Log(&r)

	// 更新当前文件大小
	l.currentSize += int64(len([]byte(fmt.Sprintf("%+v", r))))

	return nil
}

// LogSecurityInfo 记录一般安全信息
func (l *SecurityLogger) LogSecurityInfo(component, message string, data interface{}) {
	l.LogEvent(SecurityEvent{
		Level:     SecurityInfo,
		Time:      time.Now(),
		Component: component,
		Message:   message,
		Data:      data,
	})
}

// LogSecurityWarn 记录安全警告
func (l *SecurityLogger) LogSecurityWarn(component, message string, data interface{}) {
	l.LogEvent(SecurityEvent{
		Level:     SecurityWarn,
		Time:      time.Now(),
		Component: component,
		Message:   message,
		Data:      data,
	})
}

// LogSecurityError 记录安全错误
func (l *SecurityLogger) LogSecurityError(component, message string, data interface{}) {
	l.LogEvent(SecurityEvent{
		Level:     SecurityError,
		Time:      time.Now(),
		Component: component,
		Message:   message,
		Data:      data,
	})
}

// LogSecurityCritical 记录严重安全事件
func (l *SecurityLogger) LogSecurityCritical(component, message string, data interface{}) {
	l.LogEvent(SecurityEvent{
		Level:     SecurityCritical,
		Time:      time.Now(),
		Component: component,
		Message:   message,
		Data:      data,
	})
}

// LogAPIAccess 记录API访问
func (l *SecurityLogger) LogAPIAccess(component, endpoint, sourceIP, userID string, success bool, data interface{}) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	level := SecurityInfo
	if !success {
		level = SecurityWarn
	}
	
	l.LogEvent(SecurityEvent{
		Level:     level,
		Time:      time.Now(),
		Component: component,
		Message:   fmt.Sprintf("API Access %s: %s", status, endpoint),
		Data:      data,
		SourceIP:  sourceIP,
		UserID:    userID,
	})
}

// LogAuthAttempt 记录认证尝试
func (l *SecurityLogger) LogAuthAttempt(component, userID, sourceIP string, success bool, data interface{}) {
	status := "success"
	if !success {
		status = "failure"
	}
	
	level := SecurityInfo
	if !success {
		level = SecurityWarn
	}
	
	l.LogEvent(SecurityEvent{
		Level:     level,
		Time:      time.Now(),
		Component: component,
		Message:   fmt.Sprintf("Authentication %s", status),
		Data:      data,
		SourceIP:  sourceIP,
		UserID:    userID,
	})
}

// checkRotate 检查是否需要旋转日志文件
func (l *SecurityLogger) checkRotate() error {
	needRotate := false
	
	// 检查文件大小
	if l.rotateSize > 0 && l.currentSize >= l.rotateSize {
		needRotate = true
	}
	
	// 检查时间
	if !needRotate && l.rotateTime > 0 {
		if time.Since(l.lastRotate) >= l.rotateTime {
			needRotate = true
		}
	}
	
	if needRotate {
		return l.rotate()
	}
	
	return nil
}

// rotate 旋转日志文件
func (l *SecurityLogger) rotate() error {
	// 关闭当前文件
	if closer, ok := l.logFile.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("无法关闭安全日志文件: %v", err)
		}
	}
	
	// 创建新文件
	now := time.Now()
	logPath := filepath.Join(l.logDirectory, fmt.Sprintf("security_%s.log", now.Format("20060102_150405")))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("无法创建新的安全日志文件: %v", err)
	}
	
	// 更新日志记录器
	l.logFile = logFile
	l.handler = StreamHandler(logFile, TerminalFormat(false))
	l.currentSize = 0
	l.lastRotate = now
	
	return nil
}

// Close 关闭安全日志记录器
func (l *SecurityLogger) Close() error {
	l.enabled = false
	if closer, ok := l.logFile.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// DefaultSecurityLogger 是默认的安全日志记录器实例
var DefaultSecurityLogger *SecurityLogger

// InitDefaultSecurityLogger 初始化默认安全日志记录器
func InitDefaultSecurityLogger(logDir string) error {
	// 默认每100MB或每天旋转一次日志
	logger, err := NewSecurityLogger(logDir, 100*1024*1024, 24*time.Hour)
	if err != nil {
		return err
	}
	DefaultSecurityLogger = logger
	return nil
}

// LogSecurityInfo 使用默认记录器记录一般安全信息
func LogSecurityInfo(component, message string, data interface{}) {
	if DefaultSecurityLogger != nil {
		DefaultSecurityLogger.LogSecurityInfo(component, message, data)
	}
}

// LogSecurityWarn 使用默认记录器记录安全警告
func LogSecurityWarn(component, message string, data interface{}) {
	if DefaultSecurityLogger != nil {
		DefaultSecurityLogger.LogSecurityWarn(component, message, data)
	}
}

// LogSecurityError 使用默认记录器记录安全错误
func LogSecurityError(component, message string, data interface{}) {
	if DefaultSecurityLogger != nil {
		DefaultSecurityLogger.LogSecurityError(component, message, data)
	}
}

// LogSecurityCritical 使用默认记录器记录严重安全事件
func LogSecurityCritical(component, message string, data interface{}) {
	if DefaultSecurityLogger != nil {
		DefaultSecurityLogger.LogSecurityCritical(component, message, data)
	}
} 