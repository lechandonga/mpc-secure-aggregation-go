package mpc

import (
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

// DefaultStageTimeout 是单个协议阶段等待对端消息的默认截止时间。
const DefaultStageTimeout = 2 * time.Second

// Cluster 是一组本地参与方及其共享网络与（各方独立的）预处理材料库。
type Cluster struct {
	ids     []int
	leader  int
	parties map[int]*Party
	net     *Network
	banks   map[int]*TripleBank
	timeout time.Duration
	logger  func(string)
	// hook 仅供测试：在协议事件点同步触发（如 "before_result_send"）。
	hook func(me int, event string)
	// 集群级三元组 ID 分配器：保证并发会话下各参与方拿到对齐的同一份额。
	tripleMu   sync.Mutex
	tripleNext int
	tripleSize int
	tripleHeld map[string]int // sessionID -> 已分配三元组 ID
}

// Config 描述集群构造参数。
type Config struct {
	PartyIDs []int
	Triples  int
	Timeout  time.Duration
	Logf     func(string)
}

// NewCluster 构造参与方集群并完成预处理材料分发。
func NewCluster(cfg Config) (*Cluster, error) {
	if len(cfg.PartyIDs) < 2 {
		return nil, fmt.Errorf("%w: need at least 2 parties", ErrInvalidParams)
	}
	ids := append([]int(nil), cfg.PartyIDs...)
	sort.Ints(ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, fmt.Errorf("%w: duplicate party id %d", ErrInvalidParams, ids[i])
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultStageTimeout
	}
	logger := cfg.Logf
	if logger == nil {
		logger = func(string) {}
	}

	net := newNetwork(logger)
	parties := make(map[int]*Party, len(ids))
	for _, id := range ids {
		p := &Party{
			id:       id,
			net:      net,
			sessions: map[string]*session{},
			inboxes:  map[string]map[Stage]chan *Message{},
		}
		parties[id] = p
		net.parties[id] = p
	}
	banks, err := GenerateTriples(ids, cfg.Triples)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		parties[id].bank = banks[id]
	}

	return &Cluster{
		ids:        ids,
		leader:     ids[0],
		parties:    parties,
		net:        net,
		banks:      banks,
		timeout:    timeout,
		logger:     logger,
		tripleSize: cfg.Triples,
		tripleHeld: map[string]int{},
	}, nil
}

// allocTriple 原子分配一个全集群统一的三元组编号。
func (c *Cluster) allocTriple(sessionID string) (int, error) {
	c.tripleMu.Lock()
	defer c.tripleMu.Unlock()
	if id, ok := c.tripleHeld[sessionID]; ok {
		return id, nil
	}
	if c.tripleNext >= c.tripleSize {
		return 0, fmt.Errorf("%w: cluster triple pool empty", ErrMaterialExhausted)
	}
	id := c.tripleNext
	c.tripleNext++
	c.tripleHeld[sessionID] = id
	return id, nil
}

// releaseTriple 会话中止时销毁已分配材料（不回池）。
func (c *Cluster) releaseTriple(sessionID string) {
	c.tripleMu.Lock()
	delete(c.tripleHeld, sessionID)
	c.tripleMu.Unlock()
}

// PartyIDs 返回有序参与方编号。
func (c *Cluster) PartyIDs() []int { return append([]int(nil), c.ids...) }

// RemainingTriples 返回某参与方剩余预处理材料数。
func (c *Cluster) RemainingTriples(partyID int) int {
	if b, ok := c.banks[partyID]; ok {
		return b.Remaining()
	}
	return -1
}

// Transcript 返回协议交互记录快照（仅含份额/掩码，绝无明文输入）。
func (c *Cluster) Transcript() []*Message { return c.net.transcript.Snapshot() }

// CrashParty 模拟某参与方中途崩溃。
func (c *Cluster) CrashParty(id int) error {
	p, ok := c.parties[id]
	if !ok {
		return fmt.Errorf("%w: unknown party %d", ErrInvalidParams, id)
	}
	p.Crash()
	return nil
}

// SetHook 安装测试钩子（事件点：after_input_shares_sent）。
func (c *Cluster) SetHook(h func(me int, event string)) { c.hook = h }

// RestartParty 模拟重启；旧会话仍保持过期态。
func (c *Cluster) RestartParty(id int) error {
	p, ok := c.parties[id]
	if !ok {
		return fmt.Errorf("%w: unknown party %d", ErrInvalidParams, id)
	}
	p.Restart()
	return nil
}

// IsCrashed 查询参与方在线状态。
func (c *Cluster) IsCrashed(id int) bool {
	if p, ok := c.parties[id]; ok {
		return p.IsCrashed()
	}
	return true
}

func (c *Cluster) validateInputs(sessionID string, in map[int]*big.Int) error {
	if sessionID == "" {
		return fmt.Errorf("%w: empty session id", ErrInvalidParams)
	}
	if len(in) != len(c.ids) {
		return fmt.Errorf("%w: expect input from %d parties, got %d",
			ErrInvalidInput, len(c.ids), len(in))
	}
	for _, id := range c.ids {
		v, ok := in[id]
		if !ok || v == nil {
			return fmt.Errorf("%w: party %d missing input", ErrInvalidInput, id)
		}
		if err := field.Check(v); err != nil {
			return fmt.Errorf("%w: party %d: %v", ErrInvalidInput, id, err)
		}
	}
	return nil
}

// RunSum 执行一次安全聚合：所有参与方在线协同计算 Σ x_i。
// 任一方崩溃/超时都会确定性中止，返回的错误可用 errors.Is 区分原因。
func (c *Cluster) RunSum(sessionID string, inputs map[int]*big.Int) (*big.Int, error) {
	if err := c.validateInputs(sessionID, inputs); err != nil {
		return nil, err
	}
	return c.run(sessionID, OpSum, inputs, nil)
}

// RunMul 执行一次安全乘法：各参与方提供 (x_i, y_i)，
// 协同计算 (Σ x_i) * (Σ y_i)，每会话消费一份 Beaver 三元组材料。
func (c *Cluster) RunMul(sessionID string, xs, ys map[int]*big.Int) (*big.Int, error) {
	if err := c.validateInputs(sessionID, xs); err != nil {
		return nil, err
	}
	if err := c.validateInputs(sessionID, ys); err != nil {
		return nil, err
	}
	return c.run(sessionID, OpMul, xs, ys)
}

func (c *Cluster) run(id string, op Op, xs, ys map[int]*big.Int) (*big.Int, error) {
	// 阶段 0：所有参与方原子登记会话；任一方不在线则整体拒绝，不产生任何协议消息。
	sessions := make(map[int]*session, len(c.ids))
	for _, pid := range c.ids {
		s, err := c.parties[pid].registerSession(id, op, c.leader, c.ids, c.timeout)
		if err != nil {
			// 回滚已登记的会话，保证不留下半初始化状态。
			for qid, qs := range sessions {
				c.parties[qid].mu.Lock()
				qs.mu.Lock()
				qs.state = stateAborted
				qs.resErr = err
				qs.doneOnce.Do(func() { close(qs.done) })
				qs.mu.Unlock()
				c.parties[qid].mu.Unlock()
			}
			return nil, err
		}
		sessions[pid] = s
	}

	var wg sync.WaitGroup
	errs := make([]error, len(c.ids))
	for i, pid := range c.ids {
		wg.Add(1)
		go func(i, pid int) {
			defer wg.Done()
			var y map[int]*big.Int
			if op == OpMul {
				y = ys
			}
			errs[i] = c.runParty(op, sessions[pid], pid, xs[pid], valueOrNil(y, pid))
		}(i, pid)
	}
	wg.Wait()

	// 全部协同结束后取唯一结论：全部提交才输出；否则按参与方编号确定性选错。
	for i, pid := range c.ids {
		if errs[i] != nil {
			return nil, fmt.Errorf("session %q aborted (first failing party p%d): %w",
				id, pid, errs[i])
		}
	}
	res, err := c.parties[c.leader].SessionResult(id)
	if err != nil {
		return nil, err
	}
	// 交叉确认所有参与方视图一致。
	for _, pid := range c.ids {
		r, err := c.parties[pid].SessionResult(id)
		if err != nil {
			return nil, err
		}
		if r.Cmp(res) != 0 {
			return nil, fmt.Errorf("%w: party %d disagrees with leader result", ErrInconsistentView, pid)
		}
	}
	return res, nil
}

func valueOrNil(m map[int]*big.Int, id int) *big.Int {
	if m == nil {
		return nil
	}
	return m[id]
}
