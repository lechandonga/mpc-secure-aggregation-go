package mpc

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

// tripleShare 是某参与方持有的一份 Beaver 三元组份额：
// 各方持有 (a_i, b_i, c_i)，满足 Σ a_i = a, Σ b_i = b, Σ c_i = ab。
type tripleShare struct {
	ID      int
	a, b, c *big.Int
}

// TripleBank 为单个参与方管理三元组份额。
// Reserve 是原子的“两阶段占用”：同一三元组 ID 不会被分配两次；
// 同一 session 重复领取视为材料复用并被拒绝；库存不足给出可区分的耗尽错误。
// 被中止会话占用过的材料直接销毁（不回池），杜绝任何复用可能。
type TripleBank struct {
	mu          sync.Mutex
	partyID     int
	shares      []tripleShare
	next        int
	reserved    map[string]int // sessionID -> 已分配三元组 ID
	consumedIDs map[int]bool
	held        map[int]bool // 已被某会话通过 ReserveID 占走
}

// NewTripleBank 构造材料库（份额按 ID 对齐，见 GenerateTriples）。
func NewTripleBank(partyID int, shares []tripleShare) *TripleBank {
	return &TripleBank{
		partyID:     partyID,
		shares:      shares,
		reserved:    map[string]int{},
		consumedIDs: map[int]bool{},
		held:        map[int]bool{},
	}
}

// ReserveID 为 sessionID 占用集群统一分配的三元组编号 id。
// 各参与方通过集群级原子分配器拿到同一个 id，从而即使会话并发，
// 同一会话在各方拿到的也是同一组对齐份额。
func (b *TripleBank) ReserveID(sessionID string, id int) (tripleShare, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.reserved[sessionID]; dup {
		return tripleShare{}, fmt.Errorf("%w: party %d session %s already holds triple #%d",
			ErrMaterialReused, b.partyID, sessionID, b.reserved[sessionID])
	}
	if id < 0 || id >= len(b.shares) {
		return tripleShare{}, fmt.Errorf("%w: party %d triple #%d does not exist",
			ErrMaterialExhausted, b.partyID, id)
	}
	if b.held[id] {
		return tripleShare{}, fmt.Errorf("%w: party %d triple #%d already held",
			ErrMaterialReused, b.partyID, id)
	}
	b.held[id] = true
	if id >= b.next {
		b.next = id + 1
	}
	b.reserved[sessionID] = id
	return b.shares[id], nil
}

// Reserve 为 sessionID 原子占用一份材料。
//   - 库空       -> ErrMaterialExhausted
//   - 同会重复领 -> ErrMaterialReused
func (b *TripleBank) Reserve(sessionID string) (tripleShare, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.reserved[sessionID]; dup {
		return tripleShare{}, fmt.Errorf("%w: party %d session %s already holds triple #%d",
			ErrMaterialReused, b.partyID, sessionID, b.reserved[sessionID])
	}
	if b.next >= len(b.shares) {
		return tripleShare{}, fmt.Errorf("%w: party %d bank empty", ErrMaterialExhausted, b.partyID)
	}
	s := b.shares[b.next]
	b.next++
	b.reserved[sessionID] = s.ID
	return s, nil
}

// Release 会话中止时销毁其占用的材料（不回池）。
func (b *TripleBank) Release(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if id, ok := b.reserved[sessionID]; ok {
		b.consumedIDs[id] = true
		delete(b.reserved, sessionID)
	}
}

// Consume 标记材料被成功消费。重复消费返回 ErrMaterialReused。
func (b *TripleBank) Consume(sessionID string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id, ok := b.reserved[sessionID]
	if !ok {
		return 0, fmt.Errorf("%w: party %d session %s holds no reserved triple",
			ErrMaterialReused, b.partyID, sessionID)
	}
	if b.consumedIDs[id] {
		return 0, fmt.Errorf("%w: triple #%d already consumed", ErrMaterialReused, id)
	}
	b.consumedIDs[id] = true
	delete(b.reserved, sessionID)
	return id, nil
}

// Remaining 返回尚未分配的材料数量。
func (b *TripleBank) Remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.shares) - len(b.held)
}

// GenerateTriples 模拟预处理阶段：生成 count 个 Beaver 三元组，
// 返回每个参与方对齐到同一 ID 序列的材料库。
func GenerateTriples(partyIDs []int, count int) (map[int]*TripleBank, error) {
	if count < 0 {
		return nil, fmt.Errorf("%w: triple count must be >= 0", ErrInvalidParams)
	}
	n := len(partyIDs)
	if n < 2 {
		return nil, fmt.Errorf("%w: need at least 2 parties, got %d", ErrInvalidParams, n)
	}

	perParty := make(map[int][]tripleShare, n)
	for _, id := range partyIDs {
		perParty[id] = make([]tripleShare, 0, count)
	}

	for k := 0; k < count; k++ {
		a := field.MustRand()
		bv := field.MustRand()

		// a、b 各自切成 n 份；c=ab 的份额必须“相关”地构造：
		// 前 n-1 方取随机的 c_i，最后一方 c_{n-1} = ab - Σ_{i<n} c_i，
		// 从而严格保证 Σ c_i = ab（独立切分会破坏该关系）。
		aShares := additiveShares(a, n)
		bShares := additiveShares(bv, n)
		cShares := make([]*big.Int, n)
		sum := big.NewInt(0)
		for i := 0; i < n-1; i++ {
			cShares[i] = field.MustRand()
			sum = field.Add(sum, cShares[i])
		}
		cShares[n-1] = field.Sub(field.Mul(a, bv), sum)

		for i, pid := range partyIDs {
			perParty[pid] = append(perParty[pid], tripleShare{
				ID: k,
				a:  aShares[i],
				b:  bShares[i],
				c:  cShares[i],
			})
		}
	}

	banks := make(map[int]*TripleBank, n)
	for _, id := range partyIDs {
		banks[id] = NewTripleBank(id, perParty[id])
	}
	return banks, nil
}

// additiveShares 在 F_p 上把 secret 切成 n 份加法份额（最后一份吸收差量）。
func additiveShares(secret *big.Int, n int) []*big.Int {
	out := make([]*big.Int, n)
	acc := big.NewInt(0)
	for i := 0; i < n-1; i++ {
		out[i] = field.MustRand()
		acc = field.Add(acc, out[i])
	}
	out[n-1] = field.Sub(secret, acc)
	return out
}
