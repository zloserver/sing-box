package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	trackerConnectFlag    = 0
	trackerProtocolID     = 0x41727101980
	trackerConnectMinSize = 16
)

const bitTorrentPrefix = "\x13BitTorrent protocol"

// ReadBitTorrentPrefix keeps the first complete read so allowed traffic can
// resume copying without splitting its initial write.
func ReadBitTorrentPrefix(reader io.Reader, payload *buf.Buffer) error {
	for {
		n, err := payload.ReadOnceFrom(reader)
		length := min(payload.Len(), len(bitTorrentPrefix))
		if string(payload.Bytes()[:length]) != bitTorrentPrefix[:length] {
			return os.ErrInvalid
		}
		if length == len(bitTorrentPrefix) {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

// BitTorrent detects an unencrypted BitTorrent peer handshake.
func BitTorrent(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var header [len(bitTorrentPrefix)]byte
	err := ReadBitTorrentPrefix(reader, buf.With(header[:]))
	if err == nil {
		metadata.Protocol = C.ProtocolBitTorrent
	} else if errors.Is(err, io.EOF) {
		return E.Cause1(ErrNeedMoreData, err)
	}
	return err
}

func BitTorrentPacket(ctx context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if UDPTracker(ctx, metadata, packet) == nil || dhtQuery(packet) {
		metadata.Protocol = C.ProtocolBitTorrent
		return nil
	}
	var detected adapter.InboundContext
	if err := UTP(ctx, &detected, packet); err != nil {
		return err
	}
	// An ordinary DNS query can share the uTP header's first bytes.
	if packet[2]&0x80 == 0 && binary.BigEndian.Uint16(packet[4:6]) > 0 &&
		binary.BigEndian.Uint32(packet[6:10]) == 0 {
		_ = DomainNameQuery(ctx, &detected, packet)
		if detected.Protocol == C.ProtocolDNS {
			return os.ErrInvalid
		}
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

func dhtQuery(packet []byte) bool {
	// shortcut: recognize canonical BEP 5 queries; use a KRPC parser if extensions need coverage.
	const args = "d1:ad2:id20:"
	const queryType = "1:y1:qe"
	if len(packet) < len(args)+20+len(queryType) ||
		!bytes.HasPrefix(packet, []byte(args)) || !bytes.HasSuffix(packet, []byte(queryType)) {
		return false
	}
	query := packet[len(args)+20:]
	return bytes.Contains(query, []byte("e1:q4:ping1:t")) ||
		bytes.Contains(query, []byte("e1:q9:find_node1:t")) ||
		bytes.Contains(query, []byte("e1:q9:get_peers1:t")) ||
		bytes.Contains(query, []byte("e1:q13:announce_peer1:t"))
}

// UTP detects if the packet is a uTP connection packet.
// For the uTP protocol specification, see
//  1. https://www.bittorrent.org/beps/bep_0029.html
//  2. https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
func UTP(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	// A valid uTP packet must be at least 20 bytes long.
	if len(packet) < 20 {
		return os.ErrInvalid
	}

	version := packet[0] & 0x0F
	ty := packet[0] >> 4
	if version != 1 || ty > 4 {
		return os.ErrInvalid
	}

	// Validate the extensions
	extension := packet[1]
	reader := bytes.NewReader(packet[20:])
	for extension != 0 {
		if extension > 0x04 {
			return os.ErrInvalid
		}
		err := binary.Read(reader, binary.BigEndian, &extension)
		if err != nil {
			return err
		}
		var length byte
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return err
		}
		if int(length) > reader.Len() {
			return os.ErrInvalid
		}
		_, err = reader.Seek(int64(length), io.SeekCurrent)
		if err != nil {
			return err
		}
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// UDPTracker detects if the packet is a UDP Tracker Protocol packet.
// For the UDP Tracker Protocol specification, see https://www.bittorrent.org/beps/bep_0015.html
func UDPTracker(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if len(packet) < trackerConnectMinSize {
		return os.ErrInvalid
	}
	if binary.BigEndian.Uint64(packet[:8]) != trackerProtocolID {
		return os.ErrInvalid
	}
	if binary.BigEndian.Uint32(packet[8:12]) != trackerConnectFlag {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}
