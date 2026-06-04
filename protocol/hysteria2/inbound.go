package hysteria2

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router       adapter.Router
	logger       log.ContextLogger
	listener     *listener.Listener
	tlsConfig    tls.ServerConfig
	service      *hysteria2.Service[int]
	usersAccess  sync.RWMutex
	users        []option.Hysteria2User
	userNameList []string
	tracker      *ConnectionTracker
	ipTracker    *ConnectionTracker
}

func GetHysteria2ActiveUserCount(currInbound adapter.Inbound) int {
	h2Inbound, ok := currInbound.(*Inbound)
	if !ok {
		return 0
	}

	return h2Inbound.tracker.Count()
}

func GetHysteria2ActiveIpCount(currInbound adapter.Inbound) int {
	h2Inbound, ok := currInbound.(*Inbound)
	if !ok {
		return 0
	}

	return h2Inbound.ipTracker.Count()
}

// GetHysteria2Users returns the current user list of a hysteria2 inbound.
// It returns an empty slice for any other inbound type.
func GetHysteria2Users(currInbound adapter.Inbound) []option.Hysteria2User {
	h2Inbound, ok := currInbound.(*Inbound)
	if !ok {
		return []option.Hysteria2User{}
	}

	h2Inbound.usersAccess.RLock()
	defer h2Inbound.usersAccess.RUnlock()
	return h2Inbound.users
}

// SetHysteria2Users hot-swaps the user list of a hysteria2 inbound without a
// restart. It returns false if currInbound is not a hysteria2 inbound.
func SetHysteria2Users(currInbound adapter.Inbound, users []option.Hysteria2User) bool {
	h2Inbound, ok := currInbound.(*Inbound)
	if !ok {
		return false
	}

	userList := make([]int, len(users))
	userNameList := make([]string, len(users))
	userPasswordList := make([]string, len(users))
	for index, user := range users {
		userList[index] = index
		userNameList[index] = user.Name
		userPasswordList[index] = user.Password
	}

	h2Inbound.usersAccess.Lock()
	defer h2Inbound.usersAccess.Unlock()
	h2Inbound.users = users
	h2Inbound.userNameList = userNameList
	h2Inbound.service.UpdateUsers(userList, userPasswordList)

	return true
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2InboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	var masqueradeHandler http.Handler
	if options.Masquerade != nil && options.Masquerade.Type != "" {
		switch options.Masquerade.Type {
		case C.Hysterai2MasqueradeTypeFile:
			masqueradeHandler = http.FileServer(http.Dir(options.Masquerade.FileOptions.Directory))
		case C.Hysterai2MasqueradeTypeProxy:
			masqueradeURL, err := url.Parse(options.Masquerade.ProxyOptions.URL)
			if err != nil {
				return nil, E.Cause(err, "parse masquerade URL")
			}
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					if !options.Masquerade.ProxyOptions.RewriteHost {
						r.Out.Host = r.In.Host
					}
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
			}
		case C.Hysterai2MasqueradeTypeString:
			masqueradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if options.Masquerade.StringOptions.StatusCode != 0 {
					w.WriteHeader(options.Masquerade.StringOptions.StatusCode)
				}
				for key, values := range options.Masquerade.StringOptions.Headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.Write([]byte(options.Masquerade.StringOptions.Content))
			})
		default:
			return nil, E.New("unknown masquerade type: ", options.Masquerade.Type)
		}
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeHysteria2, tag),
		router:  router,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		tlsConfig: tlsConfig,
		tracker:   NewConnectionTracker(),
		ipTracker: NewConnectionTracker(),
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	service, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:               ctx,
		Logger:                logger,
		BrutalDebug:           options.BrutalDebug,
		SendBPS:               uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:            uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword:    salamanderPassword,
		TLSConfig:             tlsConfig,
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            udpTimeout,
		Handler:               inbound,
		MasqueradeHandler:     masqueradeHandler,
	})
	if err != nil {
		return nil, err
	}
	userList := make([]int, 0, len(options.Users))
	userNameList := make([]string, 0, len(options.Users))
	userPasswordList := make([]string, 0, len(options.Users))
	for index, user := range options.Users {
		userList = append(userList, index)
		userNameList = append(userNameList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
	}
	service.UpdateUsers(userList, userPasswordList)
	inbound.service = service
	inbound.users = options.Users
	inbound.userNameList = userNameList
	return inbound, nil
}

// userName returns the configured name for a user index in a thread-safe way,
// tolerating a concurrent user-list swap.
func (h *Inbound) userName(userID int) string {
	h.usersAccess.RLock()
	defer h.usersAccess.RUnlock()
	if userID < 0 || userID >= len(h.userNameList) {
		return ""
	}
	return h.userNameList[userID]
}

// trackConnection registers an active connection for the given user index and
// source IP, returning the configured user name (may be empty) and an onClose
// handler that releases the tracked entries when the connection ends.
func (h *Inbound) trackConnection(userID int, source M.Socksaddr, onClose N.CloseHandlerFunc) (string, N.CloseHandlerFunc) {
	userName := h.userName(userID)
	trackKey := userName
	if trackKey == "" {
		trackKey = F.ToString(userID)
	}
	ip := source.AddrString()
	h.tracker.Add(trackKey)
	h.ipTracker.Add(ip)
	wrappedOnClose := N.CloseHandlerFunc(func(err error) {
		h.tracker.Remove(trackKey)
		h.ipTracker.Remove(ip)
		if onClose != nil {
			onClose(err)
		}
	})
	return userName, wrappedOnClose
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = h.listener.ListenOptions().InboundOptions
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	userName, wrappedOnClose := h.trackConnection(userID, source, onClose)
	if userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, wrappedOnClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = h.listener.ListenOptions().InboundOptions
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	userName, wrappedOnClose := h.trackConnection(userID, source, onClose)
	if userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, wrappedOnClose)
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.service.Start(packetConn)
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.service),
	)
}
