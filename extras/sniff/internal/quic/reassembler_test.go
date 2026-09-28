package quic

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"testing"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	"github.com/stretchr/testify/require"
)

// buildClientHello builds a TLS ClientHello handshake message (including the
// 4-byte handshake header) with the given server name. An empty server name
// omits the server_name extension entirely.
func buildClientHello(sni string) []byte {
	var ext []byte
	if sni != "" {
		host := []byte(sni)
		sniEntry := []byte{0x00, byte(len(host) >> 8), byte(len(host))}
		sniEntry = append(sniEntry, host...)
		sniList := append([]byte{byte(len(sniEntry) >> 8), byte(len(sniEntry))}, sniEntry...)
		sniExt := append([]byte{0x00, 0x00, byte(len(sniList) >> 8), byte(len(sniList))}, sniList...)
		ext = append([]byte{byte(len(sniExt) >> 8), byte(len(sniExt))}, sniExt...)
	}

	body := []byte{0x03, 0x03}                // legacy_version: TLS 1.2
	body = append(body, make([]byte, 32)...)  // random
	body = append(body, 0x00)                 // legacy_session_id: empty
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)           // compression_methods: null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// appendReasmVarint appends a QUIC variable-length integer.
func appendReasmVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<22:
		return append(b, byte(v>>16)|0x80, byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>24)|0xc0, byte(v>>16), byte(v>>8), byte(v))
	}
}

// buildCryptoFrame builds a CRYPTO frame.
func buildCryptoFrame(offset uint64, data []byte) []byte {
	f := []byte{0x06}
	f = appendReasmVarint(f, offset)
	f = appendReasmVarint(f, uint64(len(data)))
	return append(f, data...)
}

// encryptInitial builds a protected QUIC Initial packet for the given version
// and DCID, carrying the given frames as its decrypted payload.
func encryptInitial(t *testing.T, version uint32, dcid []byte, pn int64, frames []byte) []byte {
	t.Helper()
	spec := reasmInitialSpec(version)
	require.NotNil(t, spec)
	secret := hkdf.Extract(crypto.SHA256.New, dcid, spec.salt)
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, secret, "client in", []byte{}, crypto.SHA256.Size())
	pk, err := NewInitialProtectionKey(clientSecret, spec.version)
	require.NoError(t, err)

	hdr := []byte{0x80 | 0x40 | spec.initialType<<4}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // SCID: empty
	hdr = appendReasmVarint(hdr, 0)
	hdr = appendReasmVarint(hdr, uint64(len(frames))+1)

	pnBytes := []byte{byte(pn)}
	aad := append(append([]byte{}, hdr...), pnBytes...)
	nonce := pk.nonce(pn)
	sealed := pk.aead.Seal(nil, nonce, frames, aad)

	// Apply header protection. The sample is 16 bytes of ciphertext taken
	// from pnOffset+4 (see RFC 9001 section 5.4.2) — with a 1-byte packet
	// number that is sealed[3:19].
	sample := sealed[3:19]
	mask := pk.headerProtection(sample)
	hdr[0] ^= mask[0] & 0x0f
	pnBytes[0] ^= mask[1]

	out := append(hdr, pnBytes...)
	return append(out, sealed...)
}

func TestClientHelloReassemblerSinglePacket(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	datagram := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch))

	done, got := r.Feed(datagram)
	require.True(t, done)
	require.NotNil(t, got)
	require.Equal(t, ch, got)

	// Feeding more datagrams after completion is a no-op.
	done, got = r.Feed([]byte{0xff, 0xff})
	require.True(t, done)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerCoalesced(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	// Two Initial packets coalesced inside one datagram, the ClientHello is
	// split across them.
	datagram := append(
		encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch[:40])),
		encryptInitial(t, V1, dcid, 1, buildCryptoFrame(40, ch[40:]))...,
	)

	done, got := r.Feed(datagram)
	require.True(t, done)
	require.NotNil(t, got)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerSplitDatagrams(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	pkt1 := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch[:40]))
	pkt2 := encryptInitial(t, V1, dcid, 1, buildCryptoFrame(40, ch[40:]))

	done, got := r.Feed(pkt1)
	require.False(t, done)
	require.Nil(t, got)

	done, got = r.Feed(pkt2)
	require.True(t, done)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerOutOfOrder(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	pkt1 := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch[:40]))
	pkt2 := encryptInitial(t, V1, dcid, 1, buildCryptoFrame(40, ch[40:]))

	// The second fragment arrives before the first one.
	done, _ := r.Feed(pkt2)
	require.False(t, done)

	done, got := r.Feed(pkt1)
	require.True(t, done)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerNonQUIC(t *testing.T) {
	r := NewClientHelloReassembler()
	// Garbage that does not even look like a long header packet.
	done, got := r.Feed([]byte{0x00, 0x01, 0x02, 0x03})
	require.True(t, done)
	require.Nil(t, got)

	// A short header packet as the first datagram is also not sniffable.
	r = NewClientHelloReassembler()
	done, got = r.Feed([]byte{0x10, 0x01, 0x02, 0x03})
	require.True(t, done)
	require.Nil(t, got)
}

func TestClientHelloReassemblerNoSNI(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("")
	dcid := []byte{1, 2, 3, 4}
	datagram := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch))

	// A ClientHello without a server name is still a complete ClientHello:
	// the decision is final and the caller decides what to do with it.
	done, got := r.Feed(datagram)
	require.True(t, done)
	require.NotNil(t, got)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerRetryEpoch(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcidA := []byte{0xaa, 0xaa, 0xaa, 0xaa}
	dcidB := []byte{0xbb, 0xbb, 0xbb, 0xbb}
	// After a Retry packet the client continues the packet number sequence
	// with new Initial keys derived from the new DCID.
	pkt1 := encryptInitial(t, V1, dcidA, 0, buildCryptoFrame(0, ch[:40]))
	pkt2 := encryptInitial(t, V1, dcidB, 1, buildCryptoFrame(40, ch[40:]))

	done, _ := r.Feed(pkt1)
	require.False(t, done)

	done, got := r.Feed(pkt2)
	require.True(t, done)
	require.Equal(t, ch, got)
}

func TestClientHelloReassemblerInputNotMutated(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	datagram := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch))
	orig := bytes.Clone(datagram)

	r.Feed(datagram)
	require.True(t, bytes.Equal(orig, datagram))
}

func TestClientHelloReassemblerCap(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	// Fragments at an offset beyond the policy cap are ignored: the
	// reassembler keeps waiting instead of learning a bogus threshold.
	r := NewClientHelloReassembler()
	frames := buildCryptoFrame(ReasmMaxCryptoData+1024, buildClientHello("snifftest.example.com"))
	done, _ := r.Feed(encryptInitial(t, V1, dcid, 0, frames))
	require.False(t, done)

	// A ClientHello whose declared length exceeds the policy cap makes the
	// reassembler give up on the session instead of buffering forever.
	r2 := NewClientHelloReassembler()
	bogus := append([]byte{0x01, 0xff, 0xff, 0xff}, make([]byte, 64)...)
	done, got := r2.Feed(encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, bogus)))
	require.True(t, done)
	require.Nil(t, got)
}

func TestClientHelloReassemblerParsedClientHello(t *testing.T) {
	r := NewClientHelloReassembler()
	ch := buildClientHello("snifftest.example.com")
	dcid := []byte{1, 2, 3, 4}
	datagram := encryptInitial(t, V1, dcid, 0, buildCryptoFrame(0, ch))

	done, got := r.Feed(datagram)
	require.True(t, done)
	// The assembled bytes must be parseable by utls, exactly like the
	// one-shot sniffing path uses them.
	clientHello := utls.UnmarshalClientHello(got)
	require.NotNil(t, clientHello)
	require.Equal(t, "snifftest.example.com", clientHello.ServerName)
}
