// Package shamir 实现素数域上的门限秘密共享（Shamir, t-of-n）。
//
// 拆分时同时产出每份份额的密码学承诺（Verifier）。恢复阶段会先校验
// 份额的域合法性与承诺，再做 Lagrange 插值；任何异常都会以可区分的
// 哨兵错误返回，绝不静默重建出一个看似合理的结果。
package shamir

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

// 可区分的拒绝原因。调用方可用 errors.Is 判定。
var (
	// ErrInvalidParams 参数非法（门限/份额数越界、秘密不在域内等）。
	ErrInvalidParams = errors.New("shamir: invalid parameters")
	// ErrInsufficientShares 合法且互不重复的份额数量未达到门限。
	ErrInsufficientShares = errors.New("shamir: not enough valid shares to reconstruct")
	// ErrShareOutOfField 份额内容不是合法域元素。
	ErrShareOutOfField = errors.New("shamir: share value out of field")
	// ErrShareIndexInvalid 份额下标不在分发范围内。
	ErrShareIndexInvalid = errors.New("shamir: share index out of range")
	// ErrShareTampered 份额与其承诺不匹配，说明份额被篡改或张冠李戴。
	ErrShareTampered = errors.New("shamir: share failed commitment check (tampered)")
	// ErrSharesInconsistent 多份份额不在同一个次数多项式上（不一致/伪造集合）。
	ErrSharesInconsistent = errors.New("shamir: shares are inconsistent with a single polynomial")
)

// Share 是编号为 X 的参与方持有的份额 (X, Y)，X 从 1 开始。
type Share struct {
	X int
	Y *big.Int
}

// Verifier 记录拆分参数与每份份额的承诺标签，恢复时必须原样提供。
type Verifier struct {
	N    int
	T    int
	tags map[int][32]byte
}

func tag(n, x int, y *big.Int) [32]byte {
	h := sha256.New()
	fmt.Fprintf(h, "shamir-share/v1|n=%d|x=%d|y=%s", n, x, y.String())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Split 在 F_p 上把 secret 拆成 n 份，任意 t 份即可恢复。
func Split(secret *big.Int, n, t int) ([]Share, *Verifier, error) {
	if n < 1 || t < 1 || t > n {
		return nil, nil, fmt.Errorf("%w: require 1 <= threshold <= total, got n=%d t=%d",
			ErrInvalidParams, n, t)
	}
	if err := field.Check(secret); err != nil {
		return nil, nil, fmt.Errorf("%w: secret: %v", ErrInvalidParams, err)
	}

	// a_0 = secret, a_1..a_{t-1} 随机，多项式 f(i)=Y_i。
	coeff := make([]*big.Int, t)
	coeff[0] = new(big.Int).Set(secret)
	for i := 1; i < t; i++ {
		coeff[i] = field.MustRand()
	}

	shares := make([]Share, n)
	v := &Verifier{N: n, T: t, tags: make(map[int][32]byte, n)}
	for i := 1; i <= n; i++ {
		xi := big.NewInt(int64(i))
		y := new(big.Int).Set(coeff[t-1])
		for j := t - 2; j >= 0; j-- {
			y = field.Add(field.Mul(y, xi), coeff[j])
		}
		shares[i-1] = Share{X: i, Y: y}
		v.tags[i] = tag(n, i, y)
	}
	return shares, v, nil
}

// CheckShare 校验单份份额的下标、域合法性与承诺。
func (v *Verifier) CheckShare(s Share) error {
	if v == nil || v.tags == nil {
		return fmt.Errorf("%w: nil verifier", ErrInvalidParams)
	}
	if s.X < 1 || s.X > v.N {
		return fmt.Errorf("%w: x=%d not in [1,%d]", ErrShareIndexInvalid, s.X, v.N)
	}
	if err := field.Check(s.Y); err != nil {
		return fmt.Errorf("%w: x=%d: %v", ErrShareOutOfField, s.X, err)
	}
	want, ok := v.tags[s.X]
	if !ok {
		return fmt.Errorf("%w: x=%d unknown to verifier", ErrInvalidParams, s.X)
	}
	if tag(v.N, s.X, s.Y) != want {
		return fmt.Errorf("%w: x=%d value does not match commitment", ErrShareTampered, s.X)
	}
	return nil
}

// Reconstruct 使用（不少于门限的）份额恢复秘密。
// 份额经过承诺校验；多于门限时还会做多项式一致性检查。
func Reconstruct(shares []Share, v *Verifier) (*big.Int, error) {
	if v == nil || v.tags == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrInvalidParams)
	}

	byX := make(map[int]*big.Int)
	for _, s := range shares {
		if err := v.CheckShare(s); err != nil {
			return nil, err
		}
		byX[s.X] = new(big.Int).Set(s.Y)
	}

	if len(byX) < v.T {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(byX), v.T)
	}

	uniq := make([]Share, 0, len(byX))
	for x, y := range byX {
		uniq = append(uniq, Share{X: x, Y: y})
	}
	// 固定下标顺序，保证任意合法份额子集恢复出的过程与结果完全确定。
	for i := 0; i < len(uniq); i++ {
		for j := i + 1; j < len(uniq); j++ {
			if uniq[j].X < uniq[i].X {
				uniq[i], uniq[j] = uniq[j], uniq[i]
			}
		}
	}

	secret := lagrangeAtZero(uniq[:v.T])

	// 超过门限：其余份额必须落在前 t 份确定的多项式上，
	// 否则说明集合本身不一致（承诺有效但互相矛盾）。
	for _, s := range uniq[v.T:] {
		if evalPoly(uniq[:v.T], big.NewInt(int64(s.X))).Cmp(s.Y) != 0 {
			return nil, fmt.Errorf("%w: share x=%d off polynomial", ErrSharesInconsistent, s.X)
		}
	}
	return secret, nil
}

// lagrangeAtZero 在 x=0 处做 Lagrange 插值。
func lagrangeAtZero(points []Share) *big.Int {
	acc := big.NewInt(0)
	for i := range points {
		num := big.NewInt(1)
		den := big.NewInt(1)
		xi := big.NewInt(int64(points[i].X))
		for j := range points {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(points[j].X))
			num = field.Mul(num, field.Neg(xj))
			den = field.Mul(den, new(big.Int).Sub(xi, xj))
		}
		inv, err := field.Inv(den)
		if err != nil {
			// 下标互不相同，分母不可能为 0。
			panic("shamir: duplicate x reached interpolation")
		}
		term := field.Mul(points[i].Y, field.Mul(num, inv))
		acc = field.Add(acc, term)
	}
	return acc
}

// evalPoly 用给定插值点对应的次数多项式（t 个点）求值 x。
func evalPoly(points []Share, x *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := range points {
		num := big.NewInt(1)
		den := big.NewInt(1)
		xi := big.NewInt(int64(points[i].X))
		for j := range points {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(points[j].X))
			num = field.Mul(num, new(big.Int).Sub(x, xj))
			den = field.Mul(den, new(big.Int).Sub(xi, xj))
		}
		inv, _ := field.Inv(den)
		term := field.Mul(points[i].Y, field.Mul(num, inv))
		acc = field.Add(acc, term)
	}
	return acc
}
