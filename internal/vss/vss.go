// Package vss 实现带 Feldman 承诺的 Shamir 门限秘密共享（t-of-n）。
//
// 秘密 s 被编码为随机 t-1 次多项式 f 的常数项，参与方 i 持有 (i, f(i))。
// 拆分时同时广播对每个系数的承诺 C_k = g^{a_k}，恢复时任何份额都必须
// 通过承诺校验，份额被篡改会得到可区分的 SHARE_TAMPERED 错误，
// 绝不会静默重建出错误结果。
package vss

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/lechandonga/mpc-secure-aggregation-go/internal/field"
	"github.com/lechandonga/mpc-secure-aggregation-go/internal/mpcerrs"
)

// Share 是某个参与方持有的份额。Index 为参与方编号（1..n），Value 为 f(Index)。
type Share struct {
	Index int
	Value *big.Int
}

// CommitmentSet 是一次拆分产生的公开承诺，C[k] = g^{a_k}（k=0 为秘密项）。
type CommitmentSet struct {
	C []*big.Int
}

// Split 把 secret 做 t-of-n Shamir 拆分，返回份额与公开承诺。
func Split(secret *big.Int, t, n int) ([]Share, CommitmentSet, error) {
	if n < 1 || t < 1 || t > n {
	return nil, CommitmentSet{}, mpcerrs.New(mpcerrs.CodeInvalidParams,
	fmt.Sprintf("require 1 <= t <= n, got t=%d n=%d", t, n))
	}
	if !field.InDomain(secret) {
	return nil, CommitmentSet{}, mpcerrs.New(mpcerrs.CodeInvalidParams,
	"secret is not a field element [0,q)")
	}

	coeff := make([]*big.Int, t)
	coeff[0] = new(big.Int).Set(secret)
	for k := 1; k < t; k++ {
	r, err := field.Rand()
	if err != nil {
	return nil, CommitmentSet{}, fmt.Errorf("vss: sample coefficient: %w", err)
	}
	coeff[k] = r
	}

	commits := make([]*big.Int, t)
	for k := range coeff {
	commits[k] = commitExp(coeff[k])
	}

	shares := make([]Share, n)
	for i := 1; i <= n; i++ {
	shares[i-1] = Share{Index: i, Value: evalPoly(coeff, big.NewInt(int64(i)))}
	}
	return shares, CommitmentSet{C: commits}, nil
}

func evalPoly(coeff []*big.Int, x *big.Int) *big.Int {
	// Horner：从最高次开始。
	y := new(big.Int).Set(coeff[len(coeff)-1])
	for k := len(coeff) - 2; k >= 0; k-- {
	y = field.Add(field.Mul(y, x), coeff[k])
	}
	return y
}

// Verify 校验单个份额与其承诺是否一致，篡改（含越界编号/数值）一律返回 false。
func Verify(s Share, cs CommitmentSet) bool {
	if s.Index < 1 || !field.InDomain(s.Value) || len(cs.C) == 0 {
	return false
	}
	x := big.NewInt(int64(s.Index))
	// g^{f(x)} = ∏ C_k^{x^k}
	rhs := big.NewInt(1)
	xPow := big.NewInt(1)
	for _, c := range cs.C {
	if c == nil || c.Sign() <= 0 || c.Cmp(groupP) >= 0 {
	return false
	}
	term := new(big.Int).Exp(c, xPow, groupP)
	rhs.Mul(rhs, term).Mod(rhs, groupP)
	xPow = field.Mul(xPow, x)
	}
	return commitExp(s.Value).Cmp(rhs) == 0
}

// Recover 用一组份额恢复秘密。校验不通过 -> SHARE_TAMPERED；
// 去重后份额不足门限 -> SHARE_TOO_FEW；同一编号出现两次 -> DUPLICATE_SHARE。
func Recover(shares []Share, cs CommitmentSet) (*big.Int, error) {
	t := len(cs.C)
	if t < 1 {
	return nil, mpcerrs.New(mpcerrs.CodeInvalidParams, "empty commitment set")
	}

	seen := make(map[int]Share, len(shares))
	for _, s := range shares {
	if !Verify(s, cs) {
	return nil, mpcerrs.New(mpcerrs.CodeShareTampered,
	fmt.Sprintf("share of party %d failed commitment verification", s.Index))
	}
	if prev, dup := seen[s.Index]; dup {
	if prev.Value.Cmp(s.Value) != 0 {
	return nil, mpcerrs.New(mpcerrs.CodeShareTampered,
	fmt.Sprintf("party %d submitted two distinct shares", s.Index))
	}
	return nil, mpcerrs.New(mpcerrs.CodeDuplicateShare,
	fmt.Sprintf("party %d submitted duplicate share", s.Index))
	}
	seen[s.Index] = s
	}

	if len(seen) < t {
	return nil, mpcerrs.New(mpcerrs.CodeShareTooFew,
	fmt.Sprintf("threshold %d requires %d valid shares, got %d", t, t, len(seen)))
	}

	uniq := make([]Share, 0, len(seen))
	for _, s := range seen {
	uniq = append(uniq, s)
	}
	return lagrangeAtZero(uniq), nil
}

// Code 便捷断言辅助：返回错误的 mpcerrs.Code，非协议错误返回空串。
func Code(err error) mpcerrs.Code {
	var e *mpcerrs.Error
	if errors.As(err, &e) {
	return e.Code
	}
	return ""
}

// lagrangeAtZero 用前 t 个已验证份额在 x=0 处做拉格朗日插值。
func lagrangeAtZero(shares []Share) *big.Int {
	t := len(shares)
	secret := big.NewInt(0)
	for i := 0; i < t; i++ {
	num := big.NewInt(1)
	den := big.NewInt(1)
	xi := big.NewInt(int64(shares[i].Index))
	for j := 0; j < t; j++ {
	if i == j {
	continue
	}
	xj := big.NewInt(int64(shares[j].Index))
	num = field.Mul(num, field.Neg(xj))       // 0 - xj
	den = field.Mul(den, new(big.Int).Sub(xi, xj))
	}
	weight := field.Mul(num, field.Inv(den))
	secret = field.Add(secret, field.Mul(shares[i].Value, weight))
	}
	return secret
}
