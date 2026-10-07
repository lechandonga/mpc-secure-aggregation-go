// Package net 提供一个进程内的参与方消息总线，用于模拟真实协议交互。
// 总线只转发密文/份额等协议消息；测试可读取 transcript 断言线上流量中
// 不包含任何参与方的明文输入。支持注入丢包/崩溃与统一截止时间（超时）。
package net

import (
	"errors"
	"sync"
	"time"
)

var ErrPartyDown = errors.New("net: party is crashed or unreachable")

// Message 是一条协议消息。Payload 只允许为协议交互数据（份额/掩码/承诺）。
type Message struct {
	Session string
	From    string
	To      string
	Tag     string
	Payload any
}

type sub struct {
	ch chan Message
}

// Bus 是线程安全的本地消息总线。
type Bus struct {
	mu          sync.Mutex
	subs        map[string]*sub
	dead        map[string]bool
	dropTag     map[string]bool
	transcript  []Message
	closedSess  map[string]bool
}

func NewBus() *Bus {
	return &Bus{
	subs:       make(map[string]*sub),
	dead:       make(map[string]bool),
	dropTag:    make(map[string]bool),
	closedSess: make(map[string]bool),
	}
}

// Register 注册一个参与方，返回其接收队列（缓冲 1024）。
func (b *Bus) Register(party string) chan Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := &sub{ch: make(chan Message, 1024)}
	b.subs[party] = s
	return s.ch
}

// Crash 模拟参与方崩溃：丢弃其队列，之后发给它的消息全部失败。
func (b *Bus) Crash(party string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.subs[party]; ok {
	close(s.ch)
	delete(b.subs, party)
	}
	b.dead[party] = true
}

// DropTag 让带指定 tag 的消息静默丢失（用于消息丢失/超时场景）。
func (b *Bus) DropTag(tag string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropTag[tag] = true
}

// CloseSession 标记会话关闭，关闭后该会话的任何消息都被总线拒绝。
func (b *Bus) CloseSession(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closedSess[session] = true
}

// Send 发送消息到接收方。
func (b *Bus) Send(m Message) error {
	b.mu.Lock()
	if b.closedSess[m.Session] {
		b.mu.Unlock()
		return errors.New("net: session is closed")
	}
	if b.dead[m.To] {
		b.mu.Unlock()
		return ErrPartyDown
	}
	if b.dropTag[m.Tag] {
		b.transcript = append(b.transcript, m)
		b.mu.Unlock()
		return nil
	}
	s, ok := b.subs[m.To]
	b.transcript = append(b.transcript, m)
	b.mu.Unlock()
	if !ok {
		return ErrPartyDown
	}
	select {
	case s.ch <- m:
		return nil
	default:
		return errors.New("net: receiver queue full")
	}
}

// Recv 在 deadline 前等待来自指定会话、可选指定 tag 的消息。
func (b *Bus) Recv(ch chan Message, session, tag string, deadline time.Time) (Message, error) {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return Message{}, errors.New("net: receive timed out")
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return Message{}, ErrPartyDown
		}
		if m.Session != session || (tag != "" && m.Tag != tag) {
			return b.Recv(ch, session, tag, deadline)
		}
		return m, nil
	case <-timeout:
		return Message{}, errors.New("net: receive timed out")
	}
}
}

// Transcript 返回截至目前所有在线消息的副本（用于泄漏审计）。
func (b *Bus) Transcript() []Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Message, len(b.transcript))
	copy(out, b.transcript)
	return out
}
