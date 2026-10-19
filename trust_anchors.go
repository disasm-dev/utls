package tls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

// TrustAnchorsExtension implements trust_anchors (0xCA34), from
// draft-ietf-tls-trust-anchor-ids. Chrome ships it from version 152.
//
// The wire shape is BoringSSL's ext_trust_anchors_add_clienthello:
//
//	CBB_add_u16(out_compressible, TLSEXT_TYPE_trust_anchors)
//	CBB_add_u16_length_prefixed(out_compressible, &contents)
//	CBB_add_u16_length_prefixed(&contents, &list)
//	CBB_add_bytes(&list, hs->config->requested_trust_anchors->data(), ...)
//
// so: type, extension length, a u16 list length, then the list. Each entry in
// the list is a single-byte length followed by that many bytes of trust anchor
// identifier, which is an encoded relative object identifier.
//
// Note that BoringSSL copies a caller-supplied blob verbatim, which means the
// ORDER is decided above BoringSSL, by the browser. Chromium keeps the
// identifiers in an absl::flat_hash_set (net/ssl/ssl_config_service.cc), and
// that set iterates in an order set by a hash seeded once per process. So one
// browser process sends one order on every connection, over TCP and QUIC
// alike, and the next process sends another. Two captures from different
// Chrome launches disagree; two connections from one launch never do. Shuffle
// reproduces that; see the comment on the field.
type TrustAnchorsExtension struct {
	// TrustAnchors is the list of trust anchor identifiers, in canonical
	// order. Each entry is an encoded relative object identifier and must be
	// at most 255 bytes.
	TrustAnchors [][]byte

	// Shuffle emits the list in this process's order: a random order drawn
	// once per process and kept for every connection, as one Chrome process
	// does, rather than the order given.
	//
	// It used to draw a fresh order for every connection. That is as visible
	// as a fixed order, just the other way round: a browser never changes the
	// order between two of its own connections, so two connections carrying
	// different orders are not one browser.
	Shuffle bool

	// emitOrder is the order used for this connection, chosen in
	// writeToUConn. Nil means emit TrustAnchors as given.
	emitOrder [][]byte
}

// processAnchorKey seeds this process's trust anchor order. It is drawn on
// first use and never changes, which is the property Chromium's per-process
// hash seed gives its set.
var (
	processAnchorKeyOnce sync.Once
	processAnchorKey     [32]byte
)

func processTrustAnchorKey() []byte {
	processAnchorKeyOnce.Do(func() {
		// crypto/rand does not fail on supported platforms. A zero key would
		// still give one stable order, which is the property that matters.
		_, _ = rand.Read(processAnchorKey[:])
	})
	return processAnchorKey[:]
}

// orderTrustAnchors returns anchors in the order a process holding key emits
// them, each identifier ranked by a keyed hash of its bytes. For one key the
// order is fixed, whatever order the list arrives in, so a TCP spec and a QUIC
// spec listing the same set agree. Across random keys every order is equally
// likely.
func orderTrustAnchors(anchors [][]byte, key []byte) [][]byte {
	type ranked struct {
		rank uint64
		ta   []byte
	}
	rs := make([]ranked, len(anchors))
	for i, ta := range anchors {
		m := hmac.New(sha256.New, key)
		m.Write(ta)
		rs[i] = ranked{binary.BigEndian.Uint64(m.Sum(nil)), ta}
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].rank != rs[j].rank {
			return rs[i].rank < rs[j].rank
		}
		return bytes.Compare(rs[i].ta, rs[j].ta) < 0
	})
	out := make([][]byte, len(rs))
	for i := range rs {
		out[i] = rs[i].ta
	}
	return out
}

func (e *TrustAnchorsExtension) list() [][]byte {
	if e.emitOrder != nil {
		return e.emitOrder
	}
	return e.TrustAnchors
}

func (e *TrustAnchorsExtension) writeToUConn(uc *UConn) error {
	if !e.Shuffle || len(e.TrustAnchors) < 2 {
		e.emitOrder = nil
		return nil
	}
	// A fresh slice rather than sorting in place, so the canonical list a spec
	// shares between connections is never reordered underneath one of them.
	e.emitOrder = orderTrustAnchors(e.TrustAnchors, processTrustAnchorKey())
	return nil
}

func (e *TrustAnchorsExtension) Len() int {
	n := 2 + 2 + 2
	for _, ta := range e.TrustAnchors {
		n += 1 + len(ta)
	}
	return n
}

func (e *TrustAnchorsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// Both lengths on the wire are u16. A list built by Write cannot exceed
	// that, because it was parsed out of a u16-prefixed field, but a caller
	// may set TrustAnchors directly, and silently truncating there would emit
	// a well-formed extension carrying the wrong bytes.
	if n := e.Len() - 6; n > 0xffff-2 {
		return 0, errors.New("tls: trust_anchors list does not fit a uint16 length")
	}
	binary.BigEndian.PutUint16(b[0:], utlsExtensionTrustAnchors)

	body := b[6:]
	listLen := 0
	for _, ta := range e.list() {
		body[0] = byte(len(ta))
		copy(body[1:], ta)
		body = body[1+len(ta):]
		listLen += 1 + len(ta)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(listLen+2)) // extension length
	binary.BigEndian.PutUint16(b[4:], uint16(listLen))   // list length
	return e.Len(), io.EOF
}

func (e *TrustAnchorsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) {
		return 0, errors.New("unable to read trust_anchors extension data")
	}
	var anchors [][]byte
	for !list.Empty() {
		var ta cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&ta) || ta.Empty() {
			return 0, errors.New("unable to read a trust_anchors entry")
		}
		anchors = append(anchors, append([]byte(nil), ta...))
	}
	e.TrustAnchors = anchors
	return fullLen, nil
}
