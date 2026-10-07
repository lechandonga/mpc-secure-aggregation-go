// Package field 定义安全计算使用的素数域 F_p，
// p = 2^64 - 2^32 + 1（Goldilocks 素数）。
//
// 所有运算结果都规范化到 [0, p)；域元素之间的相等性因此是规范的，
// 被篡改的份额一旦落在域之外即可被识别。
package field

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// P = 2^64 - 2^32 + 1
var P = func() *big.Int {
	p := new(big.Int).SetUint64(1)
	p.Lsh(p, 64)
	t := new(big.Int).SetUint64(1)
	t.Lsh(t, 32)
	p.Sub(p, t)
	p.Add(p, big.NewInt(1))
	return p
}()

// ErrNotInField 表示一个整数不是合法的域元素（负数或 >= p）。
var ErrNotInField = errors.New("value is not an element of F_p")

// Canonicalize 返回 v mod p 的规范表示（新分配的 big.Int）。
func Canonicalize(v *big.Int) *big.Int {
	return new(big.Int).Mod(v, P)
}

// Check 校验 v 是否为规范域元素。
func Check(v *big.Int) error {
	if v == nil || v.Sign() < 0 || v.Cmp(P) >= 0 {
		return ErrNotInField
	}
	return nil
}

// Add 返回 a + b mod p。
func Add(a, b *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	return r.Mod(r, P)
}

// Sub 返回 a - b mod p。
func Sub(a, b *big.Int) *big.Int {
	r := new(big.Int).Sub(a, b)
	return r.Mod(r, P)
}

// Neg 返回 -a mod p。
func Neg(a *big.Int) *big.Int {
	r := new(big.Int).Sub(P, a)
	return r.Mod(r, P)
}

// Mul 返回 a * b mod p。
func Mul(a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	return r.Mod(r, P)
}

// Inv 返回 a 在域中的乘法逆元；a=0 时返回错误。
func Inv(a *big.Int) (*big.Int, error) {
	if a.Sign() == 0 {
		return nil, errors.New("zero has no multiplicative inverse in F_p")
	}
	return new(big.Int).ModInverse(a, P), nil
}

// Exp 返回 a^e mod p。
func Exp(a, e *big.Int) *big.Int {
	return new(big.Int).Exp(a, e, P)
}

// Equal 判断两个域元素是否相等。
func Equal(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

// Rand 返回密码学随机的域元素。
func Rand() (*big.Int, error) {
	return rand.Int(rand.Reader, P)
}

// MustRand 与 Rand 相同，但在随机源失败时 panic（仅用于初始化）。
func MustRand() *big.Int {
	v, err := Rand()
	if err != nil {
		panic(err)
	}
	return v
}

// FromInt 把普通整数转换为规范域元素。
func FromInt(v int64) *big.Int {
	return Canonicalize(big.NewInt(v))
}
