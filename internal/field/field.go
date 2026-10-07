package field

import (
	"crypto/rand"
	"math/big"
)

// Q 是 RFC 3526 的 2048 位 MODP 素数，q = 2^2048 - 2^1984 - 1 + 2^64 *
// floor(2^1918 π + 124476)。VSS 承诺使用阶为 q 的循环群（指数模 q），
// 加法秘密共享也在该素数域上进行。该群无已知小因子，且 |q| 足够大。
const qHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

var (
	q     *big.Int
	qSub1 = new(big.Int)
	zero  = new(big.Int)
	one   = big.NewInt(1)
)

func init() {
	q, _ = new(big.Int).SetString(qHex, 16)
	qSub1.Sub(q, one)
}

// Mod 返回域的模数 q。
func Mod() *big.Int { return new(big.Int).Set(q) }

// Normalize 将任意整数规范到 [0,q)。
func Normalize(x *big.Int) *big.Int { return new(big.Int).Mod(x, q) }

// InDomain 判断 x 是否为域内合法元素 [0,q)。
func InDomain(x *big.Int) bool {
	return x != nil && x.Cmp(zero) >= 0 && x.Cmp(q) < 0
}

// Add 返回 a+b mod q。
func Add(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), q) }

// Sub 返回 a-b mod q。
func Sub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), q) }

// Neg 返回 -a mod q。
func Neg(a *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Neg(a), q) }

// Mul 返回 a*b mod q。
func Mul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), q) }

// Inv 返回 a 在域上的乘法逆元；a=0 时返回 nil。
func Inv(a *big.Int) *big.Int {
	if a.Sign() == 0 {
	return nil
	}
	return new(big.Int).ModInverse(a, q)
}

// Rand 返回密码学随机的域元素（用于多项式系数与加法份额盲化）。
func Rand() (*big.Int, error) { return rand.Int(rand.Reader, qSub1) }

// RandNonzero 返回域上非零随机元素（用于 Beaver 三元组的 a,b）。
func RandNonzero() (*big.Int, error) {
	for {
	x, err := Rand()
	if err != nil {
	return nil, err
	}
	if x.Sign() != 0 {
	return x, nil
	}
	}
}
