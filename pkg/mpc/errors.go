package mpc

import "errors"

// 协议级错误，全部可被 errors.Is 区分。
var (
	// ErrInvalidParams 构造集群/会话时参数非法。
	ErrInvalidParams = errors.New("mpc: invalid parameters")
	// ErrInvalidInput 参与方输入缺失或不在域内。
	ErrInvalidInput = errors.New("mpc: invalid party input")
	// ErrSessionUnknown 消息或请求指向一个该参与方从未登记过的会话。
	ErrSessionUnknown = errors.New("mpc: unknown session (possible restart)")
	// ErrSessionStale 会话已经结束/中止后被再次使用（旧会话、过期状态重放）。
	ErrSessionStale = errors.New("mpc: stale session reused after completion or abort")
	// ErrSessionExists 同一 ID 被重复登记。
	ErrSessionExists = errors.New("mpc: session already exists")
	// ErrMaterialExhausted 预处理乘法三元组材料库已耗尽。
	ErrMaterialExhausted = errors.New("mpc: preprocessing material exhausted")
	// ErrMaterialReused 同一份预处理材料被二次消费。
	ErrMaterialReused = errors.New("mpc: preprocessing material reused")
	// ErrPartyAborted 某参与方超时或崩溃，协议确定性中止。
	ErrPartyAborted = errors.New("mpc: a party aborted (timeout or crash)")
	// ErrProtocolAbort 收到对端广播的中止消息。
	ErrProtocolAbort = errors.New("mpc: protocol aborted by peer")
	// ErrStageTimeout 等待对端消息超过阶段截止时间。
	ErrStageTimeout = errors.New("mpc: stage timeout waiting for peer")
	// ErrInconsistentView 收到的消息与会话约定不符。
	ErrInconsistentView = errors.New("mpc: inconsistent protocol view")
)
