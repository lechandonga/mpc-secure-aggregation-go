package mpcerrs

// Code 是可区分的协议拒绝原因。调用方可以用 errors.Is 按类型判断，
// 也可以通过 Code 向用户展示稳定、可解释的错误类别。
type Code string

const (
	CodeInvalidParams     Code = "INVALID_PARAMS"      // 参数非法（门限/参与方编号/输入范围等）
	CodeShareTooFew       Code = "SHARE_TOO_FEW"       // 合法份额数量未达到门限
	CodeDuplicateShare    Code = "DUPLICATE_SHARE"     // 同一参与方重复提交份额
	CodeShareTampered     Code = "SHARE_TAMPERED"      // 份额未通过 VSS 承诺校验
	CodeMaterialReused    Code = "MATERIAL_REUSED"     // 预处理材料（Beaver 三元组）被重复消费
	CodeMaterialExhausted Code = "MATERIAL_EXHAUSTED"  // 预处理材料已耗尽
	CodeProtocolAborted   Code = "PROTOCOL_ABORTED"    // 有参与方超时/崩溃，协议确定性中止
	CodeSessionExpired    Code = "SESSION_EXPIRED"     // 旧会话/已结束会话被再次使用
	CodeSessionStateStale Code = "SESSION_STATE_STALE" // 重启后使用过期 epoch/状态发起请求
	CodeSessionUnknown    Code = "SESSION_UNKNOWN"     // 会话不存在
	CodeSessionConflict   Code = "SESSION_CONFLICT"    // 同一参与方在同一会话内重复/冲突请求
)

// Error 携带稳定的错误类别与上下文说明。
type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

func New(code Code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Is 使 errors.Is(err, &Error{Code: ...}) 成立，方便按类别断言。
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
	return false
	}
	return t.Code == e.Code
}
