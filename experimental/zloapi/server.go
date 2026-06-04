package zloapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

func init() {
	experimental.RegisterZloApiServerConstructor(NewServer)
}

var _ adapter.ZloApiServer = (*Server)(nil)

type Server struct {
	logger     log.Logger
	httpServer *http.Server
	endpoint   string
	inbound    adapter.InboundManager
}

func authentication(serverSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if serverSecret == "" {
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || token != serverSecret
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func NewServer(ctx context.Context, logFactory log.ObservableFactory, options option.ZloApiOptions) (adapter.ZloApiServer, error) {
	chiRouter := chi.NewRouter()
	s := &Server{
		logger: logFactory.NewLogger("zlo-api"),
		httpServer: &http.Server{
			Addr:    options.Endpoint,
			Handler: chiRouter,
		},
		endpoint: options.Endpoint,
		inbound:  service.FromContext[adapter.InboundManager](ctx),
	}

	chiRouter.Group(func(r chi.Router) {
		r.Use(authentication(options.SecretToken))
		r.Get("/", hello)
		r.Get("/stats", getStats(s))
		r.Mount("/inbound", inboundRouter(s))
	})

	return s, nil
}

func getStats(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		activeUsers := 0
		activeIps := 0

		for _, inbound := range server.inbound.Inbounds() {
			activeUsers += vless.GetVlessActiveUserCount(inbound)
			activeIps += vless.GetVlessActiveIpCount(inbound)
			activeUsers += hysteria2.GetHysteria2ActiveUserCount(inbound)
			activeIps += hysteria2.GetHysteria2ActiveIpCount(inbound)
		}

		render.JSON(w, r, render.M{
			"activeUsers": activeUsers,
			"activeIps":   activeIps,
		})
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.PlainText(w, r, "hello!")
}

func (s Server) Name() string {
	return "zlo api server"
}

func (s Server) Start(stage adapter.StartStage) error {
	switch stage {

	case adapter.StartStateStarted:
		if s.endpoint != "" {
			var (
				listener net.Listener
				err      error
			)
			for i := 0; i < 3; i++ {
				listener, err = net.Listen("tcp", s.httpServer.Addr)
				if runtime.GOOS == "android" && errors.Is(err, syscall.EADDRINUSE) {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				break
			}
			if err != nil {
				return E.Cause(err, "endpoint listen error")
			}
			s.logger.Info("restful api listening at ", listener.Addr())
			go func() {
				err = s.httpServer.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					s.logger.Error("endpoint serve error: ", err)
				}
			}()
		}
	}

	return nil
}

func (s Server) Close() error {
	return common.Close(
		common.PtrOrNil(s.httpServer),
	)
}
