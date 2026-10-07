package vss

import (
	"math/big"

	"github.com/lechandonga/mpc-secure-aggregation-go/internal/field"
)

// p = 2q+1 为 RFC 3526 的 2048 位安全素数（MODP 群）。承诺在阶为 q 的
// 子群上进行：指数算术模 q（即 field 包的域），承诺值算术模 p。
const pHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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
	groupP *big.Int
	gen    = big.NewInt(2)
)

func init() {
	groupP, _ = new(big.Int).SetString(pHex, 16)
	// 确认 2 在阶为 q 的子群中：2^q mod p == 1。
	if new(big.Int).Exp(gen, field.Mod(), groupP).Cmp(big.NewInt(1)) != 0 {
	panic("vss: generator 2 is not in the order-q subgroup")
	}
}

// GroupP 返回承诺群模数 p。
func GroupP() *big.Int { return new(big.Int).Set(groupP) }

func commitExp(e *big.Int) *big.Int { return new(big.Int).Exp(gen, e, groupP) }
