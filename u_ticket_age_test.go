package tls

import (
	"crypto/x509"
	"io"
	"testing"
	"time"
)

func TestObfuscatedTicketAge(t *testing.T) {
	const created = uint64(1_700_000_000)
	ageAdd := uint32(0xfffff000) // close enough to the top to wrap
	now := time.Unix(int64(created)+7, 654_000_000)

	var goStyle Config
	if got, want := goStyle.obfuscatedTicketAge(now, created, ageAdd), uint32(7654)+ageAdd; got != want {
		t.Errorf("millisecond age: got %d, want %d", got, want)
	}

	boring := Config{TicketAgeWholeSeconds: true}
	got := boring.obfuscatedTicketAge(now, created, ageAdd)
	if want := uint32(7000) + ageAdd; got != want {
		t.Errorf("whole-second age: got %d, want %d", got, want)
	}
	if (got-ageAdd)%1000 != 0 {
		t.Errorf("whole-second age %d leaves a millisecond remainder", got-ageAdd)
	}

	// A ticket used in the second it arrived is age zero, not a few ms.
	if got := boring.obfuscatedTicketAge(time.Unix(int64(created), 999_000_000), created, ageAdd); got != ageAdd {
		t.Errorf("same-second age: got %d, want %d", got-ageAdd, 0)
	}
}

// The age that reaches the wire, not just the arithmetic: resume a real session
// 2.345s after its ticket arrived and read the identity back out of the hello.
func TestResumedHelloTicketAge(t *testing.T) {
	issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)

	for _, tc := range []struct {
		name    string
		whole   bool
		wantAge uint32
	}{
		{"millisecond", false, 2345},
		{"whole seconds", true, 2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := testConfig.Clone()
			serverConfig.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
			serverConfig.MaxVersion = VersionTLS13
			clientConfig := &Config{
				MaxVersion:            VersionTLS13,
				ClientSessionCache:    NewLRUClientSessionCache(1),
				ServerName:            "example.golang",
				RootCAs:               roots,
				Time:                  testTime,
				TicketAgeWholeSeconds: tc.whole,
			}
			if _, _, err := testHandshake(t, clientConfig, serverConfig); err != nil {
				t.Fatalf("first handshake: %v", err)
			}
			entry := clientConfig.ClientSessionCache.(*lruSessionCache).q.Front()
			if entry == nil {
				t.Fatal("no ticket cached after the first handshake")
			}
			ageAdd := entry.Value.(*lruSessionCacheEntry).state.session.ageAdd

			clientConfig.Time = func() time.Time { return testTime().Add(2345 * time.Millisecond) }
			c, s := localPipe(t)
			defer s.Close()
			go func() {
				// Fails once s closes; only the hello matters.
				Client(c, clientConfig).Handshake()
				c.Close()
			}()
			var hdr [5]byte
			if _, err := io.ReadFull(s, hdr[:]); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			if _, err := io.ReadFull(s, body); err != nil {
				t.Fatal(err)
			}
			var hello clientHelloMsg
			if !hello.unmarshal(body) {
				t.Fatal("could not parse the resumed ClientHello")
			}
			if len(hello.pskIdentities) != 1 {
				t.Fatalf("resumed hello carries %d PSK identities, want 1", len(hello.pskIdentities))
			}
			if got := hello.pskIdentities[0].obfuscatedTicketAge - ageAdd; got != tc.wantAge {
				t.Errorf("ticket age on the wire = %dms, want %dms", got, tc.wantAge)
			}
		})
	}
}

func TestTicketAgeWholeSecondsSurvivesClone(t *testing.T) {
	c := &Config{TicketAgeWholeSeconds: true}
	if !c.Clone().TicketAgeWholeSeconds {
		t.Fatal("Clone dropped TicketAgeWholeSeconds, so a cloned config reverts to millisecond ages")
	}
}
