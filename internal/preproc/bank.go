// Package preproc 实现 Beaver 三元组预处理材料库。
//
// 材料按“参与方对”预生成：对每对参与方 (i,j)，离线生成随机 a,b 与
// c=a*b，并以二方加法共享形式分发给双方（i 持 (a_i,b_i,c_i)，
// j 持 (a_j,b_j,c_j)，满足 a_i+a_j=a、b_i+b_j=b、c_i+c_j=a*b）。
//
// 在线阶段的乘法必须通过 Allocate 原子预留一份三元组，再用 Consume 扣减。
// 重复消费（对同一预留二次扣减/二次预留同一会话方对）返回 MATERIAL_REUSED；
// 库存不足返回 MATERIAL_EXHAUSTED。银行全程加锁，多会话并发下不会重复或超发。
package preproc

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/lechandonga/mpc-secure-aggregation-go/internal/field"
	"github.com/lechandonga/mpc-secure-aggregation-go/internal/mpcerrs"
)

// PairShare 是某一方对某个成对三元组持有的份额。
type PairShare struct {
	A, B, C *big.Int
}

type stock struct {
	shareI PairShare // 发给字典序较小一方的份额
	shareJ PairShare // 发给另一方的份额
}

type reservation struct {
	session string
	used    bool
}

// Bank 是线程安全的成对 Beaver 三元组材料库。
type Bank struct {
	mu sync.Mutex
	// stocks[(i,j)] 为该方对尚未分配的三元组队列。
	stocks map[string][]stock
	// allocated[(session, i, j)] 为该会话在该方对上已预留的材料；
	// 同一 session+方对 只允许一次预留（第二次即复用）。
	allocated map[string]*reservation
	held      map[string]map[string]PairShare // session -> party -> 持有的份额（单次乘法足够）
}

func pairKey(i, j string) string {
	if i < j {
	return i + "|" + j
	}
	return j + "|" + i
}

func allocKey(session, i, j string) string {
	return session + "||" + pairKey(i, j)
}

// NewBank 构造材料库。
func NewBank() *Bank {
	return &Bank{
	stocks:    make(map[string][]stock),
	allocated: make(map[string]*reservation),
	held:      make(map[string]map[string]PairShare),
	}
}

// Generate 为每个参与方对补充 count 份三元组（离线预处理）。
func (b *Bank) Generate(parties []string, count int) error {
	if count < 0 {
	return mpcerrs.New(mpcerrs.CodeInvalidParams, "count must be >= 0")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for x := 0; x < len(parties); x++ {
	for y := x + 1; y < len(parties); y++ {
		k := pairKey(parties[x], parties[y])
		for n := 0; n < count; n++ {
			st, err := genStock()
			if err != nil {
			return err
		}
			b.stocks[k] = append(b.stocks[k], st)
		}
	}
	}
	return nil
}

func genStock() (stock, error) {
	a, err := field.RandNonzero()
	if err != nil {
	return stock{}, err
	}
	bv, err := field.RandNonzero()
	if err != nil {
	return stock{}, err
	}
	c := field.Mul(a, bv)

	ai, err := field.Rand()
	if err != nil {
	return stock{}, err
	}
	bi, err := field.Rand()
	if err != nil {
	return stock{}, err
	}
	ci, err := field.Rand()
	if err != nil {
	return stock{}, err
	}
	return stock{
	shareI: PairShare{A: ai, B: bi, C: ci},
	shareJ: PairShare{A: field.Sub(a, ai), B: field.Sub(bv, bi), C: field.Sub(c, ci)},
	}, nil
}

// Available 返回某方对剩余材料数。
func (b *Bank) Available(i, j string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.stocks[pairKey(i, j)])
}

// Allocate 为某会话在方对 (i,j) 上原子预留并分发一份三元组。
// 第二次为同一会话方对预留 -> MATERIAL_REUSED（材料复用）。
// 库存为空 -> MATERIAL_EXHAUSTED。
func (b *Bank) Allocate(session, i, j string) (PairShare, PairShare, error) {
	k := pairKey(i, j)
	b.mu.Lock()
	defer b.mu.Unlock()
	ak := allocKey(session, i, j)
	if _, exists := b.allocated[ak]; exists {
	return PairShare{}, PairShare{}, mpcerrs.New(mpcerrs.CodeMaterialReused,
		fmt.Sprintf("session %s already allocated a triple for pair %s", session, k))
	}
	q := b.stocks[k]
	if len(q) == 0 {
	return PairShare{}, PairShare{}, mpcerrs.New(mpcerrs.CodeMaterialExhausted,
		fmt.Sprintf("no preprocessed triple left for pair %s", k))
	}
	st := q[0]
	b.stocks[k] = q[1:]
	b.allocated[ak] = &reservation{session: session}

	var si, sj PairShare
	if i < j {
	si, sj = st.shareI, st.shareJ
	} else {
	si, sj = st.shareJ, st.shareI
	}
	if b.held[session] == nil {
	b.held[session] = make(map[string]PairShare)
	}
	b.held[session][i] = si
	b.held[session][j] = sj
	return si, sj, nil
}

// Consume 扣减某会话在方对 (i,j) 上预留的三元组（在线乘法成功后调用）。
// 未预留或已扣减 -> MATERIAL_REUSED。
func (b *Bank) Consume(session, i, j string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.allocated[allocKey(session, i, j)]
	if !ok {
	return mpcerrs.New(mpcerrs.CodeMaterialReused,
		fmt.Sprintf("session %s consumes an unallocated triple for pair %s", session, pairKey(i, j)))
	}
	if r.used {
	return mpcerrs.New(mpcerrs.CodeMaterialReused,
	fmt.Sprintf("session %s double-consumed triple for pair %s", session, pairKey(i, j)))
	}
	r.used = true
	return nil
}

// Release 释放某会话的全部预留（协议中止时调用，保证材料账目不残留半状态）。
// 已扣减的三元组不回补（一次性材料绝不重新流通，防止复用）。
func (b *Bank) Release(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, r := range b.allocated {
	if r.session == session {
	delete(b.allocated, k)
	}
	}
	delete(b.held, session)
}

// HeldShare 返回某会话中已分发给某方的三元组份额（供参与方执行乘法）。
func (b *Bank) HeldShare(session, party string) (PairShare, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.held[session][party]
	return s, ok
}
