// Command demo 在本地进程内模拟 3 个参与方，演示门限秘密共享、
// 安全聚合、Beaver 三元组安全乘法，以及中途崩溃的确定性中止。
package main

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/mpc"
	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/shamir"
)

func main() {
	demoShamir()
	demoSum()
	demoMul()
	demoCrash()
}

func demoShamir() {
	fmt.Println("=== 1. 门限秘密共享 (3-of-5) ===")
	secret := big.NewInt(20261007)
	shares, v, err := shamir.Split(secret, 5, 3)
	must(err)
	fmt.Printf("秘密 %s 已拆成 5 份\n", secret)

	got, err := shamir.Reconstruct([]shamir.Share{shares[0], shares[2], shares[4]}, v)
	must(err)
	fmt.Printf("用第 1/3/5 份恢复: %s\n\n", got)

	tampered := shares[2]
	tampered.Y = field.Add(tampered.Y, big.NewInt(1))
	_, err = shamir.Reconstruct([]shamir.Share{shares[0], tampered, shares[4]}, v)
	fmt.Printf("篡改第 3 份后恢复被拒绝: %v\n\n", err)
}

func demoSum() {
	fmt.Println("=== 2. 安全聚合 (3 方) ===")
	c, err := mpc.NewCluster(mpc.Config{
		PartyIDs: []int{1, 2, 3}, Triples: 4, Timeout: time.Second,
		Logf: func(s string) { fmt.Println("  交互:", s) },
	})
	must(err)
	xs := map[int]*big.Int{1: big.NewInt(10), 2: big.NewInt(20), 3: big.NewInt(30)}
	res, err := c.RunSum("sum-1", xs)
	must(err)
	fmt.Printf("结果 Σx = %s（任何交互记录都不包含 10/20/30 明文）\n\n", res)
}

func demoMul() {
	fmt.Println("=== 3. 安全乘法 (3 方, 消费 1 份 Beaver 三元组) ===")
	c, err := mpc.NewCluster(mpc.Config{
		PartyIDs: []int{1, 2, 3}, Triples: 1, Timeout: time.Second,
	})
	must(err)
	res, err := c.RunMul("mul-1",
		map[int]*big.Int{1: big.NewInt(1), 2: big.NewInt(2), 3: big.NewInt(3)},
		map[int]*big.Int{1: big.NewInt(4), 2: big.NewInt(5), 3: big.NewInt(6)})
	must(err)
	fmt.Printf("结果 (Σx)(Σy) = 6*15 = %s，剩余三元组 %d\n\n", res, c.RemainingTriples(1))

	_, err = c.RunMul("mul-2",
		map[int]*big.Int{1: big.NewInt(1), 2: big.NewInt(2), 3: big.NewInt(3)},
		map[int]*big.Int{1: big.NewInt(4), 2: big.NewInt(5), 3: big.NewInt(6)})
	if errors.Is(err, mpc.ErrMaterialExhausted) {
		fmt.Printf("材料耗尽被明确拒绝: %v\n\n", err)
	} else {
		must(err)
	}
}

func demoCrash() {
	fmt.Println("=== 4. 参与方中途崩溃 -> 确定性中止 ===")
	c, err := mpc.NewCluster(mpc.Config{
		PartyIDs: []int{1, 2, 3}, Triples: 2, Timeout: 500 * time.Millisecond,
	})
	must(err)
	c.SetHook(func(party int, event string) {
		if event == "after_input_shares_sent" && party == 3 {
			fmt.Printf("  参与方 3 在协议中途崩溃\n")
			_ = c.CrashParty(3)
		}
	})
	_, err = c.RunSum("sum-crash",
		map[int]*big.Int{1: big.NewInt(1), 2: big.NewInt(2), 3: big.NewInt(3)})
	if err != nil {
		fmt.Printf("协议中止，无部分结果: %v\n", err)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
