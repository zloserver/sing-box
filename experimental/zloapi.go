package experimental

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type ZloApiServerConstructor = func(ctx context.Context, logFactory log.ObservableFactory, options option.ZloApiOptions) (adapter.ZloApiServer, error)

var zloApiServerConstructor ZloApiServerConstructor

func RegisterZloApiServerConstructor(constructor ZloApiServerConstructor) {
	zloApiServerConstructor = constructor
}

func NewZloApiServer(ctx context.Context, logFactory log.ObservableFactory, options option.ZloApiOptions) (adapter.ZloApiServer, error) {
	if zloApiServerConstructor == nil {
		return nil, os.ErrInvalid
	}
	return zloApiServerConstructor(ctx, logFactory, options)
}
