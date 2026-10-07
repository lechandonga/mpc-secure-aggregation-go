package shamir

import (
	"errors"
	"math/big"
	"testing"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

// bizCase 是一条带业务标签的用例，t.Logf 会把覆盖的业务与每个用例的
// 通过/拒绝原因打印到 go test 日志里。
type bizCase struct {
	biz  string
	name string
	run  func(t *testing.T)
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

func mustSplit(t *testing.T, secret string, n, k int) ([]Share, *Verifier) {
	t.Helper()
	s, ok := new(big.Int).SetString(secret, 10)
	if !ok {
		t.Fatalf("bad secret")
	}
	shares, v, err := Split(s, n, k)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return shares, v
}

func TestShamirBusiness(t *testing.T) {
	cases := []bizCase{
		{
			biz: "参数非法", name: "门限超过份额数",
			run: func(t *testing.T) {
				_, _, err := Split(big.NewInt(42), 3, 4)
				if !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("want ErrInvalidParams, got %v", err)
				}
				t.Logf("拒绝原因可区分: %v", err)
			},
		},
		{
			biz: "参数非法", name: "份额数为0/门限为0",
			run: func(t *testing.T) {
				if _, _, err := Split(big.NewInt(1), 0, 0); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("n=0: %v", err)
				}
				if _, _, err := Split(big.NewInt(1), 3, 0); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("t=0: %v", err)
				}
			},
		},
		{
			biz: "参数非法", name: "秘密不在域内",
			run: func(t *testing.T) {
				bad := new(big.Int).Add(field.P, big.NewInt(1))
				if _, _, err := Split(bad, 3, 2); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("want invalid params, got %v", err)
				}
				if _, _, err := Split(big.NewInt(-1), 3, 2); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("negative: %v", err)
				}
			},
		},
		{
			biz: "参数非法", name: "nil承诺恢复",
			run: func(t *testing.T) {
				if _, err := Reconstruct([]Share{{X: 1, Y: big.NewInt(1)}}, nil); !errors.Is(err, ErrInvalidParams) {
					t.Fatalf("got %v", err)
				}
			},
		},
		{
			biz: "门限恢复", name: "恰好门限份稳定恢复",
			run: func(t *testing.T) {
				secret := big.NewInt(123456789)
				shares, v, _ := Split(secret, 5, 3)
				combos := [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}, {1, 3, 4}}
				for _, ci := range combos {
					got, err := Reconstruct([]Share{shares[ci[0]], shares[ci[1]], shares[ci[2]]}, v)
					if err != nil {
						t.Fatalf("combo %v: %v", ci, err)
					}
					if got.Cmp(secret) != 0 {
						t.Fatalf("combo %v got %s want %s", ci, got, secret)
					}
				}
				t.Logf("4 组不同合法份额子集均恢复唯一结果 %s", secret)
			},
		},
		{
			biz: "门限恢复", name: "多于门限且一致也恢复",
			run: func(t *testing.T) {
				shares, v := mustSplit(t, "999999999999", 5, 3)
				got, err := Reconstruct(shares, v)
				if err != nil || got.String() != "999999999999" {
					t.Fatalf("got %s, err %v", got, err)
				}
			},
		},
		{
			biz: "份额不足", name: "合法份额数量低于门限",
			run: func(t *testing.T) {
				shares, v := mustSplit(t, "7", 5, 3)
				_, err := Reconstruct(shares[:2], v)
				if !errors.Is(err, ErrInsufficientShares) {
					t.Fatalf("want insufficient, got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
		{
			biz: "份额不足", name: "空份额集",
			run: func(t *testing.T) {
				_, v := mustSplit(t, "7", 5, 3)
				if _, err := Reconstruct(nil, v); !errors.Is(err, ErrInsufficientShares) {
					t.Fatalf("got %v", err)
				}
			},
		},
		{
			biz: "份额篡改", name: "篡改份额值不通过承诺",
			run: func(t *testing.T) {
				shares, v := mustSplit(t, "42", 5, 3)
				tampered := []Share{shares[0], shares[1], {X: 3, Y: big.NewInt(0)}}
				_, err := Reconstruct(tampered, v)
				if !errors.Is(err, ErrShareTampered) {
					t.Fatalf("want tampered, got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
		{
			biz: "份额篡改", name: "份额值越界",
			run: func(t *testing.T) {
				shares, v := mustSplit(t, "42", 5, 3)
				bad := shares[2]
				bad.Y = new(big.Int).Add(field.P, big.NewInt(1))
				_, err := Reconstruct([]Share{shares[0], shares[1], bad}, v)
				if !errors.Is(err, ErrShareOutOfField) {
					t.Fatalf("want out-of-field, got %v", err)
				}
			},
		},
		{
			biz: "份额篡改", name: "下标越界",
			run: func(t *testing.T) {
				shares, v := mustSplit(t, "42", 5, 3)
				bad := shares[0]
				bad.X = 9
				_, err := Reconstruct([]Share{bad, shares[1], shares[2]}, v)
				if !errors.Is(err, ErrShareIndexInvalid) {
					t.Fatalf("want index invalid, got %v", err)
				}
			},
		},
		{
			biz: "份额篡改", name: "冒用另一组拆分的份额",
			run: func(t *testing.T) {
				_, v := mustSplit(t, "42", 5, 3)
				other, _ := mustSplit(t, "42", 5, 3)
				// 相同秘密的不同拆分，份额值与本承诺不匹配。
				_, err := Reconstruct(other[:3], v)
				if !errors.Is(err, ErrShareTampered) {
					t.Fatalf("want tampered, got %v", err)
				}
			},
		},
		{
			biz: "份额篡改", name: "承诺有效但集合不一致",
			run: func(t *testing.T) {
				// 绕过承诺的构造：同一 verifier 下手工制作 4 份“合法标签但不同多项式”
				// 的份额是不可能的；改用内部构造：拆两组，混合各自 2 份合法份额，
				// 再为混合集合成一个包含这些标签的 verifier（白盒测试）。
				secret1 := big.NewInt(11)
				secret2 := big.NewInt(22)
				s1, v1, _ := Split(secret1, 5, 2)
				s2, _, _ := Split(secret2, 5, 2)
				mixed := []Share{s1[0], s2[1], s1[2], s2[3]}
				v := &Verifier{N: 5, T: 2, tags: map[int][32]byte{
					1: v1.tags[1], 2: tag(5, 2, s2[1].Y),
					3: v1.tags[3], 4: tag(5, 4, s2[3].Y),
				}}
				_, err := Reconstruct(mixed, v)
				if !errors.Is(err, ErrSharesInconsistent) {
					t.Fatalf("want inconsistent, got %v", err)
				}
				t.Logf("拒绝原因: %v", err)
			},
		},
	}
	runBizCases(t, cases)
}
