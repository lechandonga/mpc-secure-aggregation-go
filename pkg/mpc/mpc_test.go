package mpc

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

type bizCase struct {
	biz  string
	name string
	run  func(t *testing.T)
}

func TestCrashAndTimeout(t *testing.T) {
	runBizCases(t, []bizCase{
		{
			biz: "中途退出", name: "协议开始前一方崩溃则直接拒绝且无协议消息",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}, Timeout: time.Second})
				if err := c.CrashParty(3); err != nil {
					t.Fatal(err)
				}
				_, err := c.RunSum("s", inputs(1, 2, 3))
				if !errors.Is(err, ErrPartyAborted) {
					t.Fatalf("got %v", err)
				}
				if len(c.Transcript()) != 0 {
					t.Fatalf("expected zero messages, got %d", len(c.Transcript()))
				}
				t.Logf("拒绝原因: %v（无部分结果/无半更新）", err)
			},
		},
		{
			biz: "中途退出", name: "协议中途崩溃其余方超时确定性中止",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}, Timeout: 500 * time.Millisecond})
				c.SetHook(func(me int, event string) {
					if event == "after_input_shares_sent" && me == 2 {
						_ = c.CrashParty(2)
					}
				})
				_, err := c.RunSum("s-crash", inputs(1, 2, 3))
				if err == nil {
					t.Fatal("expected abort")
				}
				if !(errors.Is(err, ErrStageTimeout) || errors.Is(err, ErrPartyAborted) ||
					errors.Is(err, ErrProtocolAbort)) {
					t.Fatalf("unexpected error class: %v", err)
				}
				for _, pid := range c.PartyIDs() {
					if r, _ := c.parties[pid].SessionResult("s-crash"); r != nil {
						t.Fatalf("party %d leaked partial result %s", pid, r)
					}
				}
				t.Logf("全体中止，无部分结果: %v", err)
			},
		},
		{
			biz: "旧会话拒绝", name: "完成后重放与重启后迟到消息均被拒绝",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}})
				if _, err := c.RunSum("sess-old", inputs(1, 2, 3)); err != nil {
					t.Fatal(err)
				}
				_, err := c.RunSum("sess-old", inputs(1, 2, 3))
				if !errors.Is(err, ErrSessionStale) {
					t.Fatalf("replay completed: %v", err)
				}
				if err := c.CrashParty(2); err != nil {
					t.Fatal(err)
				}
				if err := c.RestartParty(2); err != nil {
					t.Fatal(err)
				}
				err = c.net.Send(&Message{
					SessionID: "sess-old", From: 1, To: 2, Op: OpSum,
					Stage: stageInputShare, V: big.NewInt(1),
				})
				if !errors.Is(err, ErrSessionStale) {
					t.Fatalf("late message: %v", err)
				}
				t.Logf("旧会话重放与重启后迟到消息均被拒绝: %v", err)
			},
		},
		{
			biz: "旧会话拒绝", name: "未登记的未知会话消息被拒绝",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}})
				err := c.net.Send(&Message{
					SessionID: "ghost", From: 1, To: 2, Op: OpSum,
					Stage: stageInputShare, V: big.NewInt(1),
				})
				if !errors.Is(err, ErrSessionUnknown) {
					t.Fatalf("got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
	})
}

func TestConcurrentSessions(t *testing.T) {
	runBizCases(t, []bizCase{
		{
			biz: "并发会话", name: "并发扣减无超发且结果只取决于自身输入",
			run: func(t *testing.T) {
				const workers = 8
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}, Triples: workers})
				var wg sync.WaitGroup
				errs := make([]error, workers)
				results := make([]*big.Int, workers)
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func(w int) {
						defer wg.Done()
						id := fmt.Sprintf("conc-%d", w)
						a := int64(w + 1)
						// (a+0+0)*(a+0+0) = a^2
						res, err := c.RunMul(id,
							map[int]*big.Int{1: field.FromInt(a), 2: big.NewInt(0), 3: big.NewInt(0)},
							map[int]*big.Int{1: field.FromInt(a), 2: big.NewInt(0), 3: big.NewInt(0)})
						errs[w] = err
						results[w] = res
					}(w)
				}
				wg.Wait()
				seen := map[string]bool{}
				for w := 0; w < workers; w++ {
					if errs[w] != nil {
						t.Fatalf("worker %d: %v", w, errs[w])
					}
					want := big.NewInt(int64((w + 1) * (w + 1)))
					if results[w].Cmp(want) != 0 {
						t.Fatalf("worker %d got %s want %s", w, results[w], want)
					}
					rs := results[w].String()
					if seen[rs] {
						t.Fatalf("session result collision %s", rs)
					}
					seen[rs] = true
				}
				for _, pid := range c.PartyIDs() {
					if c.RemainingTriples(pid) != 0 {
						t.Fatalf("party %d remaining=%d, want exactly 0 (no over/under issue)",
							pid, c.RemainingTriples(pid))
					}
				}
				t.Logf("8 个并发会话各扣 1 份材料，结果分别为 a^2；材料库恰好清零")
			},
		},
		{
			biz: "并发会话", name: "材料不足时并发会话之一被确定性拒绝",
			run: func(t *testing.T) {
				const workers = 4
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}, Triples: workers - 1})
				var wg sync.WaitGroup
				rejected := make(chan error, workers)
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func(w int) {
						defer wg.Done()
						_, err := c.RunMul(fmt.Sprintf("few-%d", w),
							inputs(int64(w), 1), inputs(int64(w), 1))
						if err != nil {
							rejected <- err
						}
					}(w)
				}
				wg.Wait()
				close(rejected)
				count := 0
				for err := range rejected {
					if !errors.Is(err, ErrMaterialExhausted) {
						t.Fatalf("want exhausted, got %v", err)
					}
					count++
				}
				if count != 1 {
					t.Fatalf("want exactly 1 rejection, got %d", count)
				}
				t.Logf("4 会话抢 3 份材料：恰好 3 成功 1 耗尽拒绝，无超发")
			},
		},
	})
}

func TestSecureMultiplication(t *testing.T) {
	runBizCases(t, []bizCase{
		{
			biz: "安全乘法", name: "Beaver三元组正确相乘并扣减材料",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}, Triples: 3})
				res, err := c.RunMul("m1", inputs(1, 2, 3), inputs(4, 5, 6))
				if err != nil {
					t.Fatal(err)
				}
				// (1+2+3)*(4+5+6) = 6*15 = 90
				if res.Cmp(big.NewInt(90)) != 0 {
					t.Fatalf("want 90 got %s", res)
				}
				t.Logf("乘法结果 (Σx)(Σy) = %s", res)
				for _, pid := range c.PartyIDs() {
					if c.RemainingTriples(pid) != 2 {
						t.Fatalf("party %d remaining = %d", pid, c.RemainingTriples(pid))
					}
				}
			},
		},
		{
			biz: "材料耗尽", name: "乘法次数超过预处理材料数被拒绝",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}, Triples: 1})
				if _, err := c.RunMul("m1", inputs(1, 2), inputs(3, 4)); err != nil {
					t.Fatal(err)
				}
				_, err := c.RunMul("m2", inputs(1, 2), inputs(3, 4))
				if !errors.Is(err, ErrMaterialExhausted) {
					t.Fatalf("want exhausted, got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
		{
			biz: "材料复用", name: "同会话重复预留/消费被拒绝",
			run: func(t *testing.T) {
				bank := NewTripleBank(1, []tripleShare{{ID: 0}, {ID: 1}})
				if _, err := bank.Reserve("sess-a"); err != nil {
					t.Fatal(err)
				}
				if _, err := bank.Reserve("sess-a"); !errors.Is(err, ErrMaterialReused) {
					t.Fatalf("second reserve: %v", err)
				}
				if _, err := bank.Consume("sess-a"); err != nil {
					t.Fatal(err)
				}
				if _, err := bank.Consume("sess-a"); !errors.Is(err, ErrMaterialReused) {
					t.Fatalf("second consume: %v", err)
				}
				t.Logf("重复预留与重复消费均被可区分拒绝")
			},
		},
		{
			biz: "材料复用", name: "中止会话的材料销毁不回池",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}, Triples: 1, Timeout: time.Second})
				c.SetHook(func(me int, event string) {
					if event == "after_input_shares_sent" && me == 2 {
						_ = c.CrashParty(2)
					}
				})
				_, err := c.RunMul("m-crash", inputs(1, 2), inputs(3, 4))
				if !(errors.Is(err, ErrPartyAborted) || errors.Is(err, ErrProtocolAbort) ||
					errors.Is(err, ErrStageTimeout)) {
					t.Fatalf("want abort-ish error, got %v", err)
				}
				t.Logf("首次乘法确定性中止: %v", err)
				c.SetHook(nil)
				_ = c.RestartParty(2)
				// 重启后必须用新会话；旧会话重放会先报过期。
				_, err = c.RunMul("m-crash", inputs(1, 2), inputs(3, 4))
				if !errors.Is(err, ErrSessionStale) {
					t.Fatalf("want stale replay rejected, got %v", err)
				}
				_, err = c.RunMul("m2", inputs(1, 2), inputs(3, 4))
				if !errors.Is(err, ErrMaterialExhausted) {
					t.Fatalf("want exhausted (no reuse), got %v", err)
				}
				t.Logf("旧会话被拒且材料未回池: %v", err)
			},
		},
	})
}

func runBizCases(t *testing.T, cases []bizCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.biz+"/"+tc.name, func(t *testing.T) {
			t.Logf("业务[%s] 用例[%s] 开始", tc.biz, tc.name)
			tc.run(t)
			t.Logf("业务[%s] 用例[%s] 通过", tc.biz, tc.name)
		})
	}
}

func inputs(vals ...int64) map[int]*big.Int {
	m := map[int]*big.Int{}
	for i, v := range vals {
		m[i+1] = field.FromInt(v)
	}
	return m
}

func TestClusterConstruction(t *testing.T) {
	runBizCases(t, []bizCase{
		{
			biz: "参数非法", name: "参与方少于2个",
			run: func(t *testing.T) {
				if _, err := NewCluster(Config{PartyIDs: []int{1}}); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("got %v", err)
				}
			},
		},
		{
			biz: "参数非法", name: "参与方编号重复",
			run: func(t *testing.T) {
				if _, err := NewCluster(Config{PartyIDs: []int{1, 2, 2}}); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("got %v", err)
				}
			},
		},
	})
}

func TestSecureAggregation(t *testing.T) {
	runBizCases(t, []bizCase{
		{
			biz: "安全聚合", name: "正确求和且交互记录无明文输入",
			run: func(t *testing.T) {
				c, err := NewCluster(Config{PartyIDs: []int{1, 2, 3}, Triples: 0,
					Logf: func(s string) { t.Logf("  网络消息 %s", s) }})
				if err != nil {
					t.Fatal(err)
				}
				in := inputs(10, 20, 30)
				res, err := c.RunSum("s1", in)
				if err != nil {
					t.Fatal(err)
				}
				if res.Cmp(big.NewInt(60)) != 0 {
					t.Fatalf("want 60 got %s", res)
				}
				t.Logf("聚合结果 = %s", res)
				for _, m := range c.Transcript() {
					if m.Stage == stageInputShare {
						for _, plain := range []*big.Int{in[1], in[2], in[3]} {
							if m.V != nil && m.V.Cmp(plain) == 0 {
								t.Fatalf("transcript leaked plaintext input %s", plain)
							}
						}
					}
				}
			},
		},
		{
			biz: "参数非法", name: "缺少一方输入",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2, 3}})
				_, err := c.RunSum("s", map[int]*big.Int{1: big.NewInt(1), 2: big.NewInt(2)})
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
		{
			biz: "参数非法", name: "输入不在域内",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}})
				in := inputs(1, 2)
				in[2] = new(big.Int).Add(field.P, big.NewInt(1))
				if _, err := c.RunSum("s", in); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("got %v", err)
				}
			},
		},
		{
			biz: "参数非法", name: "空会话ID",
			run: func(t *testing.T) {
				c, _ := NewCluster(Config{PartyIDs: []int{1, 2}})
				if _, err := c.RunSum("", inputs(1, 2)); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("got %v", err)
				}
			},
		},
	})
}
