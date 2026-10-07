package mpc

import (
	"fmt"
	"math/big"
	"sync"
	"time"
)

const sessionInboxCap = 256

type sessionState int

const (
	stateRunning   sessionState = 1
	stateCommitted sessionState = 2
	stateAborted   sessionState = 3
)

// Party 是一个本地模拟参与方：拥有独立的材料库、会话表与崩溃状态。
type Party struct {
	id   int
	net  *Network
	bank *TripleBank

	mu       sync.Mutex
	sessions map[string]*session
	inboxes  map[string]map[Stage]chan *Message
	crashed  bool
}

type session struct {
	id      string
	op      Op
	leader  int
	parties []int
	timeout time.Duration

	mu     sync.Mutex
	state  sessionState
	resErr error
	result *big.Int

	doneOnce sync.Once
	done     chan struct{}
}

func (p *Party) deliver(m *Message) error {
	p.mu.Lock()
	if p.crashed {
		p.mu.Unlock()
		return fmt.Errorf("%w: party %d is crashed/offline", ErrPartyAborted, p.id)
	}
	s, ok := p.sessions[m.SessionID]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: party %d has no session %q", ErrSessionUnknown, p.id, m.SessionID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateRunning {
		return fmt.Errorf("%w: party %d session %q already finished",
			ErrSessionStale, p.id, s.id)
	}
	if m.Op != s.op {
		return fmt.Errorf("%w: session %q op mismatch", ErrInconsistentView, s.id)
	}
	p.mu.Lock()
	stageInboxes := p.inboxes[s.id]
	p.mu.Unlock()
	if stageInboxes == nil {
		return fmt.Errorf("%w: party %d session %q has no inbox", ErrSessionUnknown, p.id, s.id)
	}
	ch := stageInboxes[m.Stage]
	if ch == nil {
		return fmt.Errorf("%w: party %d session %q stage %d not expected",
			ErrInconsistentView, p.id, s.id, m.Stage)
	}
	select {
	case ch <- m:
		return nil
	default:
		return fmt.Errorf("%w: party %d session %q inbox overflow", ErrInconsistentView, p.id, s.id)
	}
}

// registerSession 在参与方上登记新会话。旧会话重放会得到可区分的拒绝。
func (p *Party) registerSession(id string, op Op, leader int, parties []int, timeout time.Duration) (*session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.crashed {
		return nil, fmt.Errorf("%w: party %d is crashed/offline", ErrPartyAborted, p.id)
	}
	if existing, ok := p.sessions[id]; ok {
		existing.mu.Lock()
		st := existing.state
		existing.mu.Unlock()
		if st == stateRunning {
			return nil, fmt.Errorf("%w: session %q already active on party %d", ErrSessionExists, id, p.id)
		}
		return nil, fmt.Errorf("%w: session %q already finished on party %d", ErrSessionStale, id, p.id)
	}
	inbox := map[Stage]chan *Message{}
	for _, st := range []Stage{stageAbort, stageInputShare, stageMaskShare, stageResultShare, stageOutput, stageAck} {
		inbox[st] = make(chan *Message, sessionInboxCap)
	}
	s := &session{
		id:      id,
		op:      op,
		leader:  leader,
		parties: parties,
		timeout: timeout,
		state:   stateRunning,
		done:    make(chan struct{}),
	}
	p.sessions[id] = s
	p.inboxes[id] = inbox
	return s, nil
}

// Crash 模拟参与方崩溃/掉线：不再接收或处理任何消息，
// 既有会话立即对持有者呈现中止态，不会留下半更新状态。
func (p *Party) Crash() {
	p.mu.Lock()
	p.crashed = true
	sessions := make([]*session, 0, len(p.sessions))
	for _, ss := range p.sessions {
		sessions = append(sessions, ss)
	}
	p.mu.Unlock()

	for _, s := range sessions {
		s.mu.Lock()
		if s.state == stateRunning {
			s.state = stateAborted
			s.resErr = fmt.Errorf("%w: local party %d crashed", ErrPartyAborted, p.id)
			s.doneOnce.Do(func() { close(s.done) })
		}
		s.mu.Unlock()
	}
}

// inbox 返回某会话在该参与方上的独立收件箱。
func (p *Party) inbox(sessionID string, st Stage) chan *Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inboxes[sessionID] == nil {
		return nil
	}
	return p.inboxes[sessionID][st]
}

// Restart 模拟参与方重启：崩溃标记解除，但历史会话表保留，
// 因此重启后用旧会话 ID 继续发消息仍会被识别为过期状态。
func (p *Party) Restart() {
	p.mu.Lock()
	p.crashed = false
	p.mu.Unlock()
}

// IsCrashed 返回崩溃标记。
func (p *Party) IsCrashed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.crashed
}

// SessionResult 返回已提交会话的输出；未结束/已中止返回对应错误。
func (p *Party) SessionResult(id string) (*big.Int, error) {
	p.mu.Lock()
	s, ok := p.sessions[id]
	crashed := p.crashed
	p.mu.Unlock()
	if crashed {
		return nil, fmt.Errorf("%w: party %d is crashed/offline", ErrPartyAborted, p.id)
	}
	if !ok {
		return nil, fmt.Errorf("%w: party %d never saw session %q", ErrSessionUnknown, p.id, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case stateCommitted:
		return new(big.Int).Set(s.result), nil
	case stateAborted:
		return nil, s.resErr
	default:
		return nil, fmt.Errorf("%w: session %q still running on party %d", ErrSessionStale, id, p.id)
	}
}
