package mpc

import (
	"fmt"
	"math/big"
	"sync"
)

// Op 标识会话执行的协议类型。
type Op int

const (
	// OpUnknown 未设置
	OpUnknown Op = 0
	// OpSum 安全聚合：输出 Σ x_i
	OpSum Op = 1
	// OpMul 安全乘法：输出 (Σ x_i) * (Σ y_i)
	OpMul Op = 2
)

// Stage 标识消息所属协议阶段，用于校验过期/错位消息。
type Stage int

const (
	stageAbort       Stage = 0
	stageInputShare  Stage = 1 // 各参与方分发输入的加法份额
	stageMaskShare   Stage = 2 // 乘法：公开 d、e 的份额
	stageResultShare Stage = 3 // 各方把输出份额交给 leader
	stageOutput      Stage = 4 // leader 广播最终结果
	stageAck         Stage = 5 // 对最终结果的确认
)

// BroadcastTo 广播消息的接收方标记。
const BroadcastTo = -1

// Message 是参与方之间的唯一交互载荷。
// 注意：协议设计保证 V、W 永远是份额或公开掩码，绝不包含任何一方的明文输入。
type Message struct {
	SessionID string
	From      int
	To        int
	Op        Op
	Stage     Stage
	V         *big.Int
	W         *big.Int
	AbortCode string // 仅 stageAbort 使用：可解释的中止原因码
}

func (m *Message) String() string {
	switch m.Stage {
	case stageAbort:
		return fmt.Sprintf("[%s] ABORT p%d->p%d code=%s", m.SessionID, m.From, m.To, m.AbortCode)
	default:
		return fmt.Sprintf("[%s] stage=%d p%d->p%d v=%s", m.SessionID, m.Stage, m.From, m.To, m.V.Text(16)[:min(10, len(m.V.Text(16)))])
	}
}

// Transcript 是一次集群运行的交互记录（只含份额/掩码，不含明文输入）。
type Transcript struct {
	mu       sync.Mutex
	Messages []*Message
}

func (t *Transcript) append(m *Message) {
	t.mu.Lock()
	t.Messages = append(t.Messages, m)
	t.mu.Unlock()
}

// Snapshot 返回交互记录的拷贝。
func (t *Transcript) Snapshot() []*Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Message, len(t.Messages))
	copy(out, t.Messages)
	return out
}

// Network 模拟本地进程内网络：负责按 (party, session) 投递消息、
// 丢弃崩溃参与方的消息，并记录全部交互。
type Network struct {
	mu         sync.Mutex
	parties    map[int]*Party
	transcript *Transcript
	logger     func(string)
}

func newNetwork(logger func(string)) *Network {
	if logger == nil {
		logger = func(string) {}
	}
	return &Network{parties: map[int]*Party{}, transcript: &Transcript{}, logger: logger}
}

// Send 同步把消息投递给接收方会话。返回的错误表示投递被明确拒绝
// （未知会话/过期状态/对端已崩溃），协议方应据此中止。
func (n *Network) Send(m *Message) error {
	n.mu.Lock()
	to := m.To
	from, fromOK := n.parties[m.From]
	party, ok := n.parties[to]
	n.mu.Unlock()

	if fromOK && from.IsCrashed() {
		return fmt.Errorf("%w: sender party %d is crashed/offline", ErrPartyAborted, m.From)
	}

	cp := *m
	if m.V != nil {
		cp.V = new(big.Int).Set(m.V)
	}
	if m.W != nil {
		cp.W = new(big.Int).Set(m.W)
	}
	n.transcript.append(&cp)
	n.logger(cp.String())

	if !ok {
		return fmt.Errorf("%w: recipient party %d does not exist", ErrPartyAborted, to)
	}
	return party.deliver(&cp)
}

// Broadcast 向除自己外的所有在线参与方发送中止消息；离线方静默跳过。
func (n *Network) Broadcast(m *Message) {
	n.mu.Lock()
	ids := make([]int, 0, len(n.parties))
	for id := range n.parties {
		if id != m.From {
			ids = append(ids, id)
		}
	}
	n.mu.Unlock()
	for _, id := range ids {
		cp := *m
		cp.To = id
		_ = n.Send(&cp) // 中止广播是尽力而为：离线方依赖超时中止
	}
}
