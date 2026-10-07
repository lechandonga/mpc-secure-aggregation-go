package mpc

import (
	"fmt"
	"math/big"
	"time"

	"github.com/lechandonga/mpc-secure-aggregation-go/pkg/field"
)

// scatter 把本方数组的第 i 个槽位发给第 i 个参与方（自己不发）。
// 关键：槽位按“接收方在参与方列表中的位置”对齐，发送时跳过自己
// 绝不允许按遍历序号移位，否则 n>=3 时份额会错配。
func (c *Cluster) scatter(s *session, me int, op Op, st Stage,
	slot func(i int) (v, w *big.Int)) error {
	for i, to := range c.ids {
		if to == me {
			continue
		}
		v, w := slot(i)
		if err := c.net.Send(&Message{
			SessionID: s.id, From: me, To: to, Op: op, Stage: st, V: v, W: w,
		}); err != nil {
			return err
		}
	}
	return nil
}

// gather 收集其他所有参与方在指定阶段发来的消息。
func (c *Cluster) gather(s *session, me int, st Stage) ([]*Message, error) {
	got, err := c.waitStage(s, me, st, others(c.ids, me), nil)
	if err != nil {
		return nil, err
	}
	out := make([]*Message, 0, len(got))
	for _, from := range others(c.ids, me) {
		out = append(out, got[from])
	}
	return out, nil
}

func (c *Cluster) afterInputShares(me int) {
	if c.hook != nil {
		c.hook(me, "after_input_shares_sent")
	}
}

// runParty 是单个参与方在单个会话内的协议状态机。
// 任何错误都会走 abort 路径：释放材料、广播中止、把会话置为中止态。
func (c *Cluster) runParty(op Op, s *session, me int, x, y *big.Int) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = c.abort(s, me, "panic", fmt.Errorf("internal panic: %v", r))
		}
	}()

	var ts tripleShare
	if op == OpMul {
		id, err := c.allocTriple(s.id)
		if err != nil {
			return c.abort(s, me, "material", err)
		}
		ts, err = c.parties[me].bank.ReserveID(s.id, id)
		if err != nil {
			return c.abort(s, me, "material", err)
		}
	}

	var result *big.Int
	var err error
	switch op {
	case OpSum:
		result, err = c.runSum(s, me, x)
	case OpMul:
		result, err = c.runMul(s, me, x, y, ts)
	default:
		err = fmt.Errorf("%w: unknown op %d", ErrInvalidParams, op)
	}
	if err != nil {
		return c.abort(s, me, "protocol", err)
	}

	// 提交握手：leader 收齐 ack 后才整体提交，保证“全部成功或全部中止”。
	if me == c.leader {
		if _, err := c.waitStage(s, me, stageAck, others(c.ids, me), nil); err != nil {
			return c.abort(s, me, "ack", err)
		}
	}
	if op == OpMul {
		if _, err := c.parties[me].bank.Consume(s.id); err != nil {
			return c.abort(s, me, "material", err)
		}
	}

	s.mu.Lock()
	s.state = stateCommitted
	s.result = result
	s.doneOnce.Do(func() { close(s.done) })
	s.mu.Unlock()
	return nil
}

// runSum 安全聚合：x 的加法份额分发 -> 各方本地求和 -> leader 聚合并广播。
func (c *Cluster) runSum(s *session, me int, x *big.Int) (*big.Int, error) {
	myIdx := indexOf(c.ids, me)
	vShares := additiveShares(x, len(c.ids))
	myV := vShares[myIdx]

	if err := c.scatter(s, me, OpSum, stageInputShare,
		func(i int) (*big.Int, *big.Int) { return vShares[i], nil }); err != nil {
		return nil, err
	}
	c.afterInputShares(me)

	got, err := c.gather(s, me, stageInputShare)
	if err != nil {
		return nil, err
	}
	outShare := new(big.Int).Set(myV)
	for _, m := range got {
		outShare = field.Add(outShare, m.V)
	}
	return c.commitOutput(s, me, OpSum, outShare)
}

// runMul Beaver 三元组乘法：
//  1. 分发输入份额，得到 X=Σx, Y=Σy 的本地份额；
//  2. d = X - a, e = Y - b 公开重构（仅泄露随机掩码）；
//  3. 每方计算 z_i = c_i + d*b_i + e*a_i + d*e/n，leader 聚合即 XY。
func (c *Cluster) runMul(s *session, me int, x, y *big.Int, ts tripleShare) (*big.Int, error) {
	myIdx := indexOf(c.ids, me)
	xShares := additiveShares(x, len(c.ids))
	yShares := additiveShares(y, len(c.ids))

	if err := c.scatter(s, me, OpMul, stageInputShare,
		func(i int) (*big.Int, *big.Int) { return xShares[i], yShares[i] }); err != nil {
		return nil, err
	}
	c.afterInputShares(me)

	got, err := c.gather(s, me, stageInputShare)
	if err != nil {
		return nil, err
	}
	xShare := new(big.Int).Set(xShares[myIdx])
	yShare := new(big.Int).Set(yShares[myIdx])
	for _, m := range got {
		xShare = field.Add(xShare, m.V)
		yShare = field.Add(yShare, m.W)
	}

	// d_i = X_i - a_i, e_i = Y_i - b_i，分发并公开重构 d、e。
	dShare := field.Sub(xShare, ts.a)
	eShare := field.Sub(yShare, ts.b)
	if err := c.scatter(s, me, OpMul, stageMaskShare,
		func(int) (*big.Int, *big.Int) { return dShare, eShare }); err != nil {
		return nil, err
	}
	mg, err := c.gather(s, me, stageMaskShare)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).Set(dShare)
	e := new(big.Int).Set(eShare)
	for _, m := range mg {
		d = field.Add(d, m.V)
		e = field.Add(e, m.W)
	}

	// z_i = c_i + d*b_i + e*a_i + d*e/n：常量项 d*e 由 n 方均摊，
	// Σ z_i = c + db + ea + de = XY。
	zShare := field.Add(ts.c, field.Add(field.Mul(d, ts.b), field.Mul(e, ts.a)))
	invN, err := field.Inv(big.NewInt(int64(len(c.ids))))
	if err != nil {
		return nil, err
	}
	zShare = field.Add(zShare, field.Mul(field.Mul(d, e), invN))
	return c.commitOutput(s, me, OpMul, zShare)
}

// commitOutput 输出份额汇聚到 leader，leader 重构结果并广播；
// follower 等待广播并校验结果份额的一致性视图。
func (c *Cluster) commitOutput(s *session, me int, op Op, outShare *big.Int) (*big.Int, error) {
	isLeader := me == c.leader
	if isLeader {
		got, err := c.waitStage(s, me, stageResultShare, others(c.ids, me), nil)
		if err != nil {
			return nil, err
		}
		result := new(big.Int).Set(outShare)
		for _, from := range others(c.ids, me) {
			result = field.Add(result, got[from].V)
		}
		for _, to := range c.ids {
			if to == me {
				continue
			}
			if err := c.net.Send(&Message{
				SessionID: s.id, From: me, To: to, Op: op,
				Stage: stageOutput, V: result,
			}); err != nil {
				return nil, err
			}
		}
		return result, nil
	}

	if err := c.net.Send(&Message{
		SessionID: s.id, From: me, To: c.leader, Op: op,
		Stage: stageResultShare, V: outShare,
	}); err != nil {
		return nil, err
	}
	og, err := c.waitStage(s, me, stageOutput, []int{c.leader}, nil)
	if err != nil {
		return nil, err
	}
	result := new(big.Int).Set(og[c.leader].V)

	// follower 发送提交确认。
	if err := c.net.Send(&Message{
		SessionID: s.id, From: me, To: c.leader, Op: op,
		Stage: stageAck,
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// waitStage 等待 froms 集合中各参与方指定阶段的消息。
// 收到 abort 或超过阶段截止时间都给出可区分错误。
func (c *Cluster) waitStage(s *session, me int, want Stage, froms []int, extra map[string]bool) (map[int]*Message, error) {
	need := make(map[int]bool, len(froms))
	for _, f := range froms {
		need[f] = true
	}
	got := make(map[int]*Message, len(froms))
	deadline := time.NewTimer(s.timeout)
	defer deadline.Stop()
	abortCh := c.parties[me].inbox(s.id, stageAbort)
	inbox := c.parties[me].inbox(s.id, want)
	if inbox == nil {
		return nil, fmt.Errorf("%w: session %q disappeared on party %d", ErrSessionUnknown, s.id, me)
	}

	for len(need) > 0 {
		select {
		case m := <-inbox:
			if m.Stage != want {
				return nil, fmt.Errorf("%w: party %d sent stage %d, want %d",
					ErrInconsistentView, m.From, m.Stage, want)
			}
			if !need[m.From] {
				return nil, fmt.Errorf("%w: unexpected message from party %d at stage %d",
					ErrInconsistentView, m.From, want)
			}
			delete(need, m.From)
			got[m.From] = m
		case m := <-abortCh:
			return nil, fmt.Errorf("%w: party %d aborted session with code %s",
				ErrProtocolAbort, m.From, m.AbortCode)
		case <-s.done:
			return nil, fmt.Errorf("%w: local party stopped session %q", ErrPartyAborted, s.id)
		case <-deadline.C:
			missing := make([]int, 0, len(need))
			for id := range need {
				missing = append(missing, id)
			}
			return nil, fmt.Errorf("%w: party %d waited stage %d, missing from %v",
				ErrStageTimeout, me, want, missing)
		}
	}
	return got, nil
}

// abort 确定性中止：会话置中止态、释放（销毁）预处理材料、尽力广播 abort。
func (c *Cluster) abort(s *session, me int, code string, cause error) error {
	s.mu.Lock()
	if s.state != stateRunning {
		err := s.resErr
		s.mu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: already finished", ErrSessionStale)
	}
	wrapped := cause
	s.state = stateAborted
	s.resErr = wrapped
	s.doneOnce.Do(func() { close(s.done) })
	s.mu.Unlock()

	if s.op == OpMul {
		c.parties[me].bank.Release(s.id)
		c.releaseTriple(s.id)
	}

	c.net.Broadcast(&Message{
		SessionID: s.id, From: me, To: BroadcastTo, Op: s.op,
		Stage: stageAbort, AbortCode: code,
	})
	return wrapped
}

func others(ids []int, me int) []int {
	out := make([]int, 0, len(ids)-1)
	for _, id := range ids {
		if id != me {
			out = append(out, id)
		}
	}
	return out
}

func indexOf(ids []int, id int) int {
	for i, v := range ids {
		if v == id {
			return i
		}
	}
	return -1
}
