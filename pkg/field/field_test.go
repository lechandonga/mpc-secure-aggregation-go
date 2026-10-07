package field

import (
	"math/big"
	"testing"
)

func TestFieldArithmetic(t *testing.T) {
	if got := Add(FromInt(-2), FromInt(5)); got.Cmp(FromInt(3)) != 0 {
		t.Fatalf("negative canonicalize: %s", got)
	}
	if got := Mul(new(big.Int).Set(P), FromInt(7)); got.Sign() != 0 {
		t.Fatalf("p*7 mod p: %s", got)
	}
	if got := Neg(big.NewInt(2)); Add(got, big.NewInt(2)).Sign() != 0 {
		t.Fatalf("neg(2)+2: %s", got)
	}
	inv, err := Inv(big.NewInt(12345))
	if err != nil {
		t.Fatal(err)
	}
	if Mul(big.NewInt(12345), inv).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("inverse check failed")
	}
	if err := Check(new(big.Int).Sub(P, big.NewInt(1))); err != nil {
		t.Fatalf("p-1 should be valid: %v", err)
	}
	if err := Check(P); err == nil {
		t.Fatal("p should be out of field")
	}
}
