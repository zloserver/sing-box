package zloapi

var (
	CtxKeyInboundTag = contextKey("inbound name")
	CtxKeyInbound    = contextKey("inbound")
)

type contextKey string

func (c contextKey) String() string {
	return "zlo api context key " + string(c)
}
