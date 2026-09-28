package quic

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/hkdf"
)

const (
	// ReasmMaxCryptoData bounds the size of the reassembled CRYPTO stream.
	// Real ClientHellos are a few KB even with post-quantum key exchange, so
	// this is a generous resource policy cap rather than a protocol limit.
	ReasmMaxCryptoData = 16 * 1024
)

var (
	errReasmMalformed = errors.New("malformed QUIC Initial packet")
	errReasmKey       = errors.New("cannot derive QUIC Initial keys")
)

// reasmVersionSpec carries the version-specific parameters needed to decrypt
// and parse QUIC Initial packets.
type reasmVersionSpec struct {
	version     uint32
	initialType byte
	retryType   byte
	salt        []byte
}

var reasmVersions = []reasmVersionSpec{
	{version: V1, initialType: 0b00, retryType: 0b11, salt: quicSaltV1},
	{version: V2, initialType: 0b01, retryType: 0b00, salt: quicSaltV2},
}

func reasmInitialSpec(version uint32) *reasmVersionSpec {
	for i := range reasmVersions {
		if reasmVersions[i].version == version {
			return &reasmVersions[i]
		}
	}
	return nil
}

// initialEpoch is one set of Initial protection keys. A session goes through
// at most two epochs: the server may send a Retry packet, after which the
// client derives new keys from the new connection ID while continuing the
// packet number sequence.
type initialEpoch struct {
	dcid      []byte
	protector *PacketProtector
	largestPN int64
}

// ClientHelloReassembler reassembles a TLS ClientHello from the CRYPTO frames
// of the QUIC Initial packets of a single client session. Initial packets may
// be coalesced inside one datagram or spread across multiple datagrams, and
// CRYPTO frames may arrive out of order, overlapping or duplicated.
//
// The input datagrams are never modified — decryption happens on copies — so
// the caller can still forward the original datagrams afterwards.
type ClientHelloReassembler struct {
	epochs     []initialEpoch
	crypto     []byte // reassembled CRYPTO stream
	have       []byte // coverage bitmap, 1 bit per byte of the CRYPTO stream
	contiguous int    // length of the contiguous (fully received) prefix
	started    bool   // at least one valid Initial packet has been seen
	done       bool
	ch         []byte // the complete ClientHello handshake message once done
}

func NewClientHelloReassembler() *ClientHelloReassembler {
	return &ClientHelloReassembler{}
}

// Feed feeds one UDP datagram to the reassembler. The datagram may contain
// multiple coalesced QUIC packets.
//
// Returns (done, clientHello): done=true when the decision is final — either
// a complete ClientHello has been assembled (clientHello is the full TLS
// handshake message, including the 4-byte handshake header), or the data is
// determined not to be a sniffable QUIC ClientHello session (clientHello nil).
func (r *ClientHelloReassembler) Feed(datagram []byte) (bool, []byte) {
	if r.done {
		return true, r.ch
	}
	rest := datagram
	for len(rest) > 0 {
		typeByte := rest[0]
		// Version negotiation packets have the fixed bit unset and short header
		// packets lack the long header bit. A QUIC client only sends Initial
		// packets before its handshake completes, so seeing anything else
		// before a valid Initial means this is not a sniffable QUIC session.
		if typeByte&0x80 == 0 || typeByte&0x40 == 0 {
			if !r.started {
				r.finish(nil)
			}
			return r.result()
		}
		if len(rest) < 6 { // 1 type + 4 version + 1 DCID length, minimum
			if !r.started {
				r.finish(nil)
			}
			return r.result()
		}
		version := binary.BigEndian.Uint32(rest[1:5])
		spec := reasmInitialSpec(version)
		if spec == nil {
			if !r.started {
				r.finish(nil)
			}
			return r.result()
		}
		i := 5
		dcidLen := int(rest[i])
		i++
		if len(rest) < i+dcidLen {
			return r.result()
		}
		dcid := rest[i : i+dcidLen]
		i += dcidLen
		if len(rest) < i+1 {
			return r.result()
		}
		scidLen := int(rest[i])
		i++
		if len(rest) < i+scidLen {
			return r.result()
		}
		i += scidLen
		packetType := (typeByte >> 4) & 0b11
		isInitial := packetType == spec.initialType
		if packetType == spec.retryType {
			// Retry packets are only sent by the server and have no Length
			// field — they consume the rest of the datagram. Ignore them.
			return r.result()
		}
		tokenLen := uint64(0)
		if isInitial {
			tl, n, ok := readReasmVarint(rest[i:])
			if !ok {
				return r.result()
			}
			tokenLen = tl
			i += n
			if uint64(len(rest)-i) < tokenLen {
				return r.result()
			}
			i += int(tokenLen)
		}
		length, n, ok := readReasmVarint(rest[i:])
		if !ok {
			return r.result()
		}
		i += n
		if length < 4 || len(rest)-i < int(length) {
			return r.result()
		}
		packet := rest[i : i+int(length)]

		if isInitial {
			r.started = true
			payload, err := r.decryptInitial(packet, i, dcid, spec)
			if err == nil {
				if cerr := r.collectCrypto(payload); cerr == nil {
					if done, ch := r.tryAssemble(); done {
						r.finish(ch)
						return true, r.ch
					}
				}
			}
			// Decryption or frame parsing failure: the packet is skipped and
			// sniffing continues with the rest of the datagram.
		}
		rest = rest[i+int(length):]
	}
	return r.result()
}

func (r *ClientHelloReassembler) result() (bool, []byte) { return r.done, r.ch }

func (r *ClientHelloReassembler) finish(ch []byte) {
	r.done = true
	r.ch = ch
}

// decryptInitial removes header protection and decrypts one Initial packet.
// The packet is decrypted on a copy — the input datagram is not modified.
func (r *ClientHelloReassembler) decryptInitial(packet []byte, hdrLen int, dcid []byte, spec *reasmVersionSpec) ([]byte, error) {
	ep := r.epochFor(dcid, spec)
	if ep == nil {
		return nil, errReasmKey
	}
	pkt := bytes.Clone(packet)
	payload, pn, err := ep.protector.UnProtectPN(pkt, int64(hdrLen), ep.largestPN)
	if err != nil {
		return nil, err
	}
	if pn > ep.largestPN {
		ep.largestPN = pn
	}
	return payload, nil
}

// epochFor returns the key epoch matching the given DCID, creating a new one
// (up to two are retained, see RFC 9000 section 17.2.5 on Retry) if needed.
func (r *ClientHelloReassembler) epochFor(dcid []byte, spec *reasmVersionSpec) *initialEpoch {
	for i := range r.epochs {
		if bytes.Equal(r.epochs[i].dcid, dcid) {
			return &r.epochs[i]
		}
	}
	secret := hkdf.Extract(crypto.SHA256.New, dcid, spec.salt)
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, secret, "client in", []byte{}, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(clientSecret, spec.version)
	if err != nil {
		return nil
	}
	ep := initialEpoch{
		dcid:      bytes.Clone(dcid),
		protector: NewPacketProtector(key),
		largestPN: -1,
	}
	if len(r.epochs) < 2 {
		r.epochs = append(r.epochs, ep)
	} else {
		r.epochs[1] = ep
	}
	return &r.epochs[len(r.epochs)-1]
}

// collectCrypto parses the frames of a decrypted Initial packet and collects
// the CRYPTO frame data into the reassembly buffer.
func (r *ClientHelloReassembler) collectCrypto(payload []byte) error {
	for len(payload) > 0 {
		frameType := payload[0]
		payload = payload[1:]
		switch frameType {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, ACK with ECN
			var n int
			var ok bool
			// Largest Acknowledged
			if _, n, ok = readReasmVarint(payload); !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			// ACK Delay
			if _, n, ok = readReasmVarint(payload); !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			// ACK Range Count
			var rangeCount uint64
			if rangeCount, n, ok = readReasmVarint(payload); !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			// First ACK Range
			if _, n, ok = readReasmVarint(payload); !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			// ACK Ranges (Gap + ACK Range Length per range)
			for i := uint64(0); i < rangeCount; i++ {
				if _, n, ok = readReasmVarint(payload); !ok {
					return errReasmMalformed
				}
				payload = payload[n:]
				if _, n, ok = readReasmVarint(payload); !ok {
					return errReasmMalformed
				}
				payload = payload[n:]
			}
			if frameType == 0x03 { // ECN counts: ECT0, ECT1, ECT-CE
				for i := 0; i < 3; i++ {
					if _, n, ok = readReasmVarint(payload); !ok {
						return errReasmMalformed
					}
					payload = payload[n:]
				}
			}
		case 0x06: // CRYPTO
			offset, n, ok := readReasmVarint(payload)
			if !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			length, n, ok := readReasmVarint(payload)
			if !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			if uint64(len(payload)) < length {
				return errReasmMalformed
			}
			r.addCrypto(offset, payload[:length])
			payload = payload[length:]
		case 0x1c: // CONNECTION_CLOSE, only 0x1c is permitted in Initial packets
			// Error Code, Frame Type, Reason Phrase Length
			for i := 0; i < 3; i++ {
				_, n, ok := readReasmVarint(payload)
				if !ok {
					return errReasmMalformed
				}
				payload = payload[n:]
			}
			// Reason Phrase
			rl, n, ok := readReasmVarint(payload)
			if !ok {
				return errReasmMalformed
			}
			payload = payload[n:]
			if uint64(len(payload)) < rl {
				return errReasmMalformed
			}
			payload = payload[rl:]
		default:
			// Only the frame types above are permitted in Initial packets.
			return errReasmMalformed
		}
	}
	return nil
}

// addCrypto stores a CRYPTO fragment, growing the buffer only as needed and
// tracking exact byte coverage across out-of-order, overlapping or duplicated
// fragments.
func (r *ClientHelloReassembler) addCrypto(offset uint64, data []byte) {
	if len(data) == 0 || offset+uint64(len(data)) > ReasmMaxCryptoData {
		// Oversized fragments are ignored — a real ClientHello never gets
		// even close to the cap, and exceeding it is grounds for giving up.
		return
	}
	end := int(offset + uint64(len(data)))
	if end > len(r.crypto) {
		grown := make([]byte, end)
		copy(grown, r.crypto)
		r.crypto = grown
		bm := make([]byte, (end+7)/8)
		copy(bm, r.have)
		r.have = bm
	}
	copy(r.crypto[offset:end], data)
	for i := int(offset); i < end; i++ {
		r.have[i/8] |= 1 << (i % 8)
	}
	if int(offset) <= r.contiguous {
		for r.contiguous < len(r.crypto) && r.have[r.contiguous/8]&(1<<(r.contiguous%8)) != 0 {
			r.contiguous++
		}
	}
}

// tryAssemble checks whether the contiguous prefix of the CRYPTO stream now
// contains a complete ClientHello handshake message. Returns (true, msg) when
// it does, (true, nil) when the stream is determined not to be a sniffable
// ClientHello, and (false, nil) when more data is needed.
func (r *ClientHelloReassembler) tryAssemble() (bool, []byte) {
	if r.contiguous < 4 {
		// TLS handshake header: 1 byte type + 3 bytes length
		return false, nil
	}
	if r.crypto[0] != 0x01 {
		// The first handshake message in the CRYPTO stream of a client Initial
		// is always a ClientHello — anything else is not sniffable.
		return true, nil
	}
	msgLen := int(r.crypto[1])<<16 | int(r.crypto[2])<<8 | int(r.crypto[3])
	if 4+msgLen > ReasmMaxCryptoData {
		// Policy cap exceeded, give up sniffing this session.
		return true, nil
	}
	if r.contiguous < 4+msgLen {
		// The ClientHello is not fully received yet.
		return false, nil
	}
	return true, r.crypto[:4+msgLen]
}

// readReasmVarint reads a QUIC variable-length integer from the beginning of b.
func readReasmVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length, true
}
