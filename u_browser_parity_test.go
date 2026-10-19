package tls

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// writeLog records every Write on a connection.
type writeLog struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (w *writeLog) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.writes = append(w.writes, append([]byte(nil), b...))
	w.mu.Unlock()
	return w.Conn.Write(b)
}

func (w *writeLog) since(n int) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.writes[n:]...)
}

func (w *writeLog) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes)
}

// recordTypes lists the TLS record content types in a run of raw bytes.
func recordTypes(b []byte) []recordType {
	var out []recordType
	for len(b) >= recordHeaderLen {
		n := int(b[3])<<8 | int(b[4])
		out = append(out, recordType(b[0]))
		if len(b) < recordHeaderLen+n {
			break
		}
		b = b[recordHeaderLen+n:]
	}
	return out
}

// sendKeyUpdateRequest has the server ask for a KeyUpdate, then moves the
// server to its next write key, as a peer doing so would.
func sendKeyUpdateRequest(t *testing.T, server *Conn) {
	t.Helper()
	server.out.Lock()
	defer server.out.Unlock()
	msg, err := (&keyUpdateMsg{updateRequested: true}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.writeRecordLocked(recordTypeHandshake, msg); err != nil {
		t.Fatal(err)
	}
	suite := cipherSuiteTLS13ByID(server.cipherSuite)
	server.out.setTrafficSecret(suite, QUICEncryptionLevelInitial, suite.nextTrafficSecret(server.out.trafficSecret))
}

// A KeyUpdate that asks for one back is answered straight away by Go. With
// DeferKeyUpdateReply the answer waits for the next application write and goes
// out in the same socket write as that data, as BoringSSL's pending flight
// does, so an idle connection says nothing.
func TestDeferKeyUpdateReply(t *testing.T) {
	for _, tc := range []struct {
		name   string
		defer_ bool
	}{
		{"immediate", false},
		{"deferred", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := localPipe(t)
			serverConfig := testConfig.Clone()
			serverConfig.MaxVersion = VersionTLS13
			server := Server(s, serverConfig)
			clientConfig := testConfig.Clone()
			clientConfig.MaxVersion = VersionTLS13
			clientConfig.DeferKeyUpdateReply = tc.defer_
			log := &writeLog{Conn: c}
			client := Client(log, clientConfig)

			serverErr := make(chan error, 1)
			go func() { serverErr <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			defer client.Close()
			defer server.Close()

			go func() {
				sendKeyUpdateRequest(t, server)
				server.Write([]byte("ping"))
			}()
			before := log.count()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("client read %q, %v", buf, err)
			}
			time.Sleep(50 * time.Millisecond)
			idleWrites := log.since(before)
			if tc.defer_ && len(idleWrites) != 0 {
				t.Fatalf("idle client wrote %d times after the KeyUpdate, want nothing", len(idleWrites))
			}
			if !tc.defer_ && len(idleWrites) == 0 {
				t.Fatal("immediate mode sent no KeyUpdate reply")
			}

			before = log.count()
			readDone := make(chan string, 1)
			go func() {
				b := make([]byte, 4)
				io.ReadFull(server, b)
				readDone <- string(b)
			}()
			if _, err := client.Write([]byte("pong")); err != nil {
				t.Fatalf("client write: %v", err)
			}
			select {
			case got := <-readDone:
				if got != "pong" {
					t.Fatalf("server read %q under the rotated keys", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server never read the client's data")
			}
			if tc.defer_ {
				writes := log.since(before)
				if len(writes) != 1 {
					t.Fatalf("reply and data took %d socket writes, want 1", len(writes))
				}
				if types := recordTypes(writes[0]); len(types) != 2 {
					t.Errorf("the write carried %d records, want KeyUpdate then data", len(types))
				}
			}
		})
	}
}

// delayedFinal holds back one of a server's writes: the Nth, which in a TLS
// 1.2 full handshake is the NewSessionTicket, ChangeCipherSpec and Finished.
// corrupt flips the last byte of that write, which lands in the Finished.
type delayedFinal struct {
	net.Conn
	n       int
	delay   time.Duration
	corrupt bool
	mu      sync.Mutex
	writes  int
}

func (d *delayedFinal) Write(b []byte) (int, error) {
	d.mu.Lock()
	d.writes++
	nth := d.writes == d.n
	d.mu.Unlock()
	if nth {
		time.Sleep(d.delay)
		if d.corrupt {
			b = append([]byte(nil), b...)
			b[len(b)-1] ^= 0xff
		}
	}
	return d.Conn.Write(b)
}

// With FalseStart a TLS 1.2 client hands the connection back as soon as its
// own Finished is out, so application data leaves before the server's
// Finished, as Chrome's does. The server's Finished is still read and checked
// before any data is returned.
func TestFalseStart(t *testing.T) {
	const hold = 400 * time.Millisecond
	for _, tc := range []struct {
		name       string
		falseStart bool
		alpn       bool
		corrupt    bool
		wantEarly  bool
	}{
		{"off", false, true, false, false},
		{"on", true, true, false, true},
		{"on without ALPN", true, false, false, false},
		{"on, bad server Finished", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := localPipe(t)
			serverConfig := testConfig.Clone()
			serverConfig.MaxVersion = VersionTLS12
			serverConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			clientConfig := testConfig.Clone()
			clientConfig.MaxVersion = VersionTLS12
			clientConfig.FalseStart = tc.falseStart
			if tc.alpn {
				serverConfig.NextProtos = []string{"h2"}
				clientConfig.NextProtos = []string{"h2"}
			}
			server := Server(&delayedFinal{Conn: s, n: 2, delay: hold, corrupt: tc.corrupt}, serverConfig)
			client := Client(c, clientConfig)
			defer client.Close()
			defer server.Close()

			serverDone := make(chan string, 1)
			go func() {
				if err := server.Handshake(); err != nil {
					serverDone <- "handshake: " + err.Error()
					return
				}
				b := make([]byte, 5)
				if _, err := io.ReadFull(server, b); err != nil {
					serverDone <- "read: " + err.Error()
					return
				}
				server.Write([]byte("world"))
				serverDone <- string(b)
			}()

			start := time.Now()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			took := time.Since(start)
			if early := took < hold/2; early != tc.wantEarly {
				t.Fatalf("handshake returned after %v, want early (before the server Finished): %v", took, tc.wantEarly)
			}
			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatalf("client write: %v", err)
			}

			buf := make([]byte, 5)
			_, err := io.ReadFull(client, buf)
			if tc.corrupt {
				if err == nil {
					t.Fatal("a corrupted server Finished was accepted")
				}
				if _, werr := client.Write([]byte("more!")); werr == nil {
					t.Error("writes still succeed after the handshake failed")
				}
				return
			}
			if err != nil || string(buf) != "world" {
				t.Fatalf("client read %q, %v", buf, err)
			}
			if got := <-serverDone; got != "hello" {
				t.Fatalf("server side: %s", got)
			}
			if st := client.ConnectionState(); !st.HandshakeComplete || st.NegotiatedProtocol != map[bool]string{true: "h2"}[tc.alpn] {
				t.Errorf("state after the first read: complete=%v alpn=%q", st.HandshakeComplete, st.NegotiatedProtocol)
			}
		})
	}
}

// helloExtensions returns the extension types of every plaintext ClientHello
// in a client's bytes, in order: the first hello and, after a
// HelloRetryRequest, the second.
func helloExtensions(t *testing.T, raw []byte) [][]uint16 {
	t.Helper()
	var hellos [][]uint16
	var hs []byte
	for len(raw) >= recordHeaderLen {
		n := int(raw[3])<<8 | int(raw[4])
		if len(raw) < recordHeaderLen+n {
			break
		}
		typ, body := recordType(raw[0]), raw[recordHeaderLen:recordHeaderLen+n]
		raw = raw[recordHeaderLen+n:]
		if typ == recordTypeApplicationData {
			break
		}
		if typ != recordTypeHandshake {
			continue
		}
		hs = append(hs, body...)
		for len(hs) >= 4 {
			ml := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) < 4+ml {
				break
			}
			if hs[0] == typeClientHello {
				var m clientHelloMsg
				if !m.unmarshal(hs[:4+ml]) {
					t.Fatal("unparseable ClientHello")
				}
				var types []uint16
				for _, e := range m.extensions {
					types = append(types, e)
				}
				hellos = append(hellos, types)
			}
			hs = hs[4+ml:]
		}
	}
	return hellos
}

func hasExtension(types []uint16, want uint16) bool {
	for _, e := range types {
		if e == want {
			return true
		}
	}
	return false
}

// resumeThroughHRR runs one Chrome-shaped connection against a server that
// forces a HelloRetryRequest (P-256 only), reads the post-handshake tickets,
// and returns the client's connection state and every byte the client sent.
func resumeThroughHRR(t *testing.T, config *Config, spec *ClientHelloSpec) (ConnectionState, []byte, error) {
	t.Helper()
	c, s := localPipe(t)
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = VersionTLS13
	serverConfig.CurvePreferences = []CurveID{CurveP256}
	server := Server(s, serverConfig)
	go func() {
		if server.Handshake() == nil {
			server.Write([]byte("x"))
			io.Copy(io.Discard, server)
		}
		server.Close()
	}()

	log := &writeLog{Conn: c}
	uconn := UClient(log, config, HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	err := uconn.Handshake()
	if err == nil {
		// The tickets arrive after the handshake; reading data takes them in.
		b := make([]byte, 1)
		_, err = io.ReadFull(uconn, b)
	}
	st := uconn.ConnectionState()
	uconn.Close()
	var all []byte
	for _, w := range log.since(0) {
		all = append(all, w...)
	}
	return st, all, err
}

// A resumption that meets a HelloRetryRequest resumes, as BoringSSL's does:
// the second ClientHello offers the PSK again with a binder over the new
// transcript. uTLS used to abort the handshake instead.
func TestResumptionSurvivesHelloRetryRequest(t *testing.T) {
	spec := func() *ClientHelloSpec {
		s, err := UTLSIdToSpec(HelloChrome_133_PSK)
		if err != nil {
			t.Fatal(err)
		}
		return &s
	}
	config := &Config{
		ServerName:            "example.golang",
		Time:                  testConfig.Time, // the test certificate is long expired by the real clock
		InsecureSkipVerify:    true,
		ClientSessionCache:    NewLRUClientSessionCache(4),
		TicketAgeWholeSeconds: true,
		OmitEmptyPsk:          true, // the first connection has no session yet
	}

	if _, _, err := resumeThroughHRR(t, config, spec()); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	st, raw, err := resumeThroughHRR(t, config, spec())
	if err != nil {
		t.Fatalf("resumed connection: %v", err)
	}
	if !st.DidResume {
		t.Fatal("second connection did not resume")
	}
	hellos := helloExtensions(t, raw)
	if len(hellos) != 2 {
		t.Fatalf("%d ClientHellos, want 2 (the second after the HelloRetryRequest)", len(hellos))
	}
	if !hasExtension(hellos[1], extensionPreSharedKey) {
		t.Error("the second ClientHello dropped the PSK")
	}
	if last := hellos[1][len(hellos[1])-1]; last != extensionPreSharedKey {
		t.Errorf("pre_shared_key is not last in the second ClientHello: ends with %d", last)
	}
}

// When the server's HelloRetryRequest picks a cipher suite whose hash differs
// from the session's, the PSK cannot be used, and BoringSSL leaves it out of
// the second ClientHello (should_offer_psk). The handshake then completes in
// full rather than carrying a PSK with a stale binder.
func TestHelloRetryRequestDropsAnIncompatiblePSK(t *testing.T) {
	sha384, err := UTLSIdToSpec(HelloChrome_133_PSK)
	if err != nil {
		t.Fatal(err)
	}
	var suites []uint16
	for _, cs := range sha384.CipherSuites {
		if cs != TLS_AES_128_GCM_SHA256 && cs != TLS_CHACHA20_POLY1305_SHA256 {
			suites = append(suites, cs)
		}
	}
	sha384.CipherSuites = suites
	config := &Config{
		ServerName:         "example.golang",
		Time:               testConfig.Time,
		InsecureSkipVerify: true,
		ClientSessionCache: NewLRUClientSessionCache(4),
		OmitEmptyPsk:       true,
	}
	if _, _, err := resumeThroughHRR(t, config, &sha384); err != nil {
		t.Fatalf("first connection (SHA-384 session): %v", err)
	}

	chrome, err := UTLSIdToSpec(HelloChrome_133_PSK)
	if err != nil {
		t.Fatal(err)
	}
	st, raw, err := resumeThroughHRR(t, config, &chrome)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	if st.DidResume {
		t.Fatal("resumed a SHA-384 session under a SHA-256 suite")
	}
	hellos := helloExtensions(t, raw)
	if len(hellos) != 2 {
		t.Fatalf("%d ClientHellos, want 2", len(hellos))
	}
	if !hasExtension(hellos[0], extensionPreSharedKey) {
		t.Fatal("the first ClientHello did not offer the cached session, so this tests nothing")
	}
	if hasExtension(hellos[1], extensionPreSharedKey) {
		t.Error("the second ClientHello still carries the incompatible PSK")
	}
}
