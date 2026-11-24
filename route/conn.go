package route

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

type ConnectionManager struct {
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()
	for element := m.connections.Front(); element != nil; element = element.Next() {
		common.Close(element.Value)
	}
	m.connections.Init()
	return nil
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	outbound, isOutbound := this.(adapter.Outbound)
	blockTorrent := metadata.BlockBitTorrent && isOutbound && outbound.Type() == C.TypeDirect
	if blockTorrent {
		// Fast Open dials on the first write. Start it before waiting for client data.
		if earlyConn, ok := common.Cast[N.EarlyConn](remoteConn); ok && earlyConn.NeedHandshake() {
			if _, err = remoteConn.Write(nil); err != nil {
				remoteConn.Close()
				N.CloseOnHandshakeFailure(conn, onClose, err)
				m.logger.ErrorContext(ctx, "open connection: ", err)
				return
			}
		}
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	onClose = N.AppendClose(onClose, func(it error) {
		m.access.Lock()
		defer m.access.Unlock()
		m.connections.Remove(element)
	})
	var done atomic.Bool
	go m.connectionCopy(ctx, remoteConn, conn, true, &done, onClose)
	if blockTorrent {
		go m.connectionCopyChecked(ctx, conn, remoteConn, &done, onClose)
	} else {
		go m.connectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	}
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		remotePacketConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else if metadata.Destination != M.SocksaddrFrom(destinationAddress, metadata.Destination.Port) {
			if metadata.UDPDisableDomainUnmapping {
				remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), originDestination)
			} else {
				remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), originDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	var udpTimeout time.Duration
	if metadata.UDPTimeout > 0 {
		udpTimeout = metadata.UDPTimeout
	} else {
		protocol := metadata.Protocol
		if protocol == "" {
			protocol = C.PortProtocols[metadata.Destination.Port]
		}
		if protocol != "" {
			udpTimeout = C.ProtocolTimeouts[protocol]
		}
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	onClose = N.AppendClose(onClose, func(it error) {
		m.access.Lock()
		defer m.access.Unlock()
		m.connections.Remove(element)
	})
	var done atomic.Bool
	outbound, isOutbound := this.(adapter.Outbound)
	blockTorrent := metadata.BlockBitTorrent && isOutbound && outbound.Type() == C.TypeDirect
	go m.packetConnectionCopy(ctx, conn, destination, false, blockTorrent, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, false, &done, onClose)
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var (
		sourceReader      io.Reader = source
		destinationWriter io.Writer = destination
	)
	var readCounters, writeCounters []N.CountFunc
	for {
		sourceReader, readCounters = N.UnwrapCountReader(sourceReader, readCounters)
		destinationWriter, writeCounters = N.UnwrapCountWriter(destinationWriter, writeCounters)
		if cachedSrc, isCached := sourceReader.(N.CachedReader); isCached {
			cachedBuffer := cachedSrc.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err := destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					if !done.Swap(true) {
						onClose(err)
					}
					common.Close(source, destination)
					if !direction {
						m.logger.ErrorContext(ctx, "connection upload payload: ", err)
					} else {
						m.logger.ErrorContext(ctx, "connection download payload: ", err)
					}
					return
				}
				for _, counter := range readCounters {
					counter(int64(dataLen))
				}
				for _, counter := range writeCounters {
					counter(int64(dataLen))
				}
			}
			continue
		}
		break
	}
	if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](destinationWriter); isEarlyConn && earlyConn.NeedHandshake() {
		err := m.connectionCopyEarly(source, destination)
		if err != nil {
			if !done.Swap(true) {
				onClose(err)
			}
			common.Close(source, destination)
			if !direction {
				m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
			} else {
				m.logger.ErrorContext(ctx, "connection download handshake: ", err)
			}
			return
		}
	}
	_, err := bufio.CopyWithCounters(destinationWriter, sourceReader, source, readCounters, writeCounters, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	if err != nil {
		common.Close(source, destination)
	} else if duplexDst, isDuplex := destination.(N.WriteCloser); isDuplex {
		err = duplexDst.CloseWrite()
		if err != nil {
			common.Close(source, destination)
		}
	} else {
		destination.Close()
	}
	// Report the connection closed as soon as either direction ends, the same way
	// packetConnectionCopy does. Waiting for both directions leaves a half-closed
	// connection unreported until TCP keepalive expires - or indefinitely, while the
	// peer keeps its socket open - which leaks every onClose driven bookkeeping:
	// the active user tracker and the connection manager list.
	if !done.Swap(true) {
		onClose(err)
	} else {
		common.Close(source, destination)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

var errBitTorrentBlocked = (&R.RuleActionReject{Method: C.RuleActionRejectMethodDefault, NoDrop: true}).Error(nil)

func (m *ConnectionManager) connectionCopyChecked(ctx context.Context, source, destination net.Conn, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	payload := buf.New()
	err := sniff.ReadBitTorrentPrefix(source, payload)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, os.ErrInvalid):
		if payload.IsEmpty() {
			payload.Release()
		} else {
			source = bufio.NewCachedConn(source, payload)
		}
		m.connectionCopy(ctx, source, destination, false, done, onClose)
		return
	case err == nil:
		err = errBitTorrentBlocked
		m.logger.DebugContext(ctx, "blocked BitTorrent stream")
	default:
		m.logger.DebugContext(ctx, "read connection upload: ", err)
	}
	payload.Release()
	if !done.Swap(true) {
		onClose(err)
	}
	common.Close(source, destination)
}

func (m *ConnectionManager) connectionCopyEarly(source net.Conn, destination io.Writer) error {
	payload := buf.NewPacket()
	defer payload.Release()
	err := source.SetReadDeadline(time.Now().Add(C.ReadPayloadTimeout))
	if err != nil {
		if err == os.ErrInvalid {
			return common.Error(destination.Write(nil))
		}
		return err
	}
	_, err = payload.ReadOnceFrom(source)
	if err != nil && !(E.IsTimeout(err) || errors.Is(err, io.EOF)) {
		return E.Cause(err, "read payload")
	}
	_ = source.SetReadDeadline(time.Time{})
	_, err = destination.Write(payload.Bytes())
	if err != nil {
		return E.Cause(err, "write payload")
	}
	return nil
}

func copyCheckedFirstPacket(ctx context.Context, source N.PacketReader, destination N.PacketWriter) error {
	options := N.NewReadWaitOptions(source, destination)
	buffer := options.NewPacketBuffer()
	address, err := source.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return err
	}
	var metadata adapter.InboundContext
	if sniff.BitTorrentPacket(ctx, &metadata, buffer.Bytes()) == nil {
		buffer.Release()
		return errBitTorrentBlocked
	}
	options.PostReturn(buffer)
	return destination.WritePacket(buffer, address)
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction, blockTorrent bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var err error
	if blockTorrent {
		err = copyCheckedFirstPacket(ctx, source, destination)
	}
	if err == nil {
		_, err = bufio.CopyPacket(destination, source)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if R.IsRejected(err) {
			m.logger.DebugContext(ctx, "blocked BitTorrent packet")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		onClose(err)
	}
	common.Close(source, destination)
}
