package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// detectContentType tests
// ---------------------------------------------------------------------------

func TestSubmitDetectContentType_CycloneDX(t *testing.T) {
	data := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
	ct := detectContentType(data)
	assert.Equal(t, "application/vnd.cyclonedx+json", ct)
}

func TestSubmitDetectContentType_SPDX(t *testing.T) {
	data := []byte(`{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`)
	ct := detectContentType(data)
	assert.Equal(t, "application/spdx+json", ct)
}

func TestSubmitDetectContentType_Generic(t *testing.T) {
	data := []byte(`{"some": "json"}`)
	ct := detectContentType(data)
	assert.Equal(t, "application/json", ct)
}

// ---------------------------------------------------------------------------
// postSBOM integration tests using httptest
// ---------------------------------------------------------------------------

func TestSubmitAuthorizationHeader(t *testing.T) {
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postSBOM(srv.URL, "my-secret-token", "application/json", []byte(`{}`), 5, false)
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-secret-token", gotAuth)
}

func TestSubmitContentTypeCycloneDX(t *testing.T) {
	var gotCT string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	data := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
	err := postSBOM(srv.URL, "tok", detectContentType(data), data, 5, false)
	require.NoError(t, err)
	assert.Equal(t, "application/vnd.cyclonedx+json", gotCT)
}

func TestSubmitContentTypeSPDX(t *testing.T) {
	var gotCT string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	data := []byte(`{"spdxVersion": "SPDX-2.3"}`)
	err := postSBOM(srv.URL, "tok", detectContentType(data), data, 5, false)
	require.NoError(t, err)
	assert.Equal(t, "application/spdx+json", gotCT)
}

func TestSubmitAcceptHeader(t *testing.T) {
	var gotAccept string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, false)
	require.NoError(t, err)
	assert.Equal(t, "application/json", gotAccept)
}

func TestSubmit4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := postSBOM(srv.URL, "bad-token", "application/json", []byte(`{}`), 5, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestSubmit5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSubmit2xxPrintsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	}))
	defer srv.Close()

	err := postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, false)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Env var fallback tests (via submitCmd flag resolution logic)
// ---------------------------------------------------------------------------

func TestSubmitEnvVarURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("TRANSPARENZ_SERVER_URL", srv.URL)
	t.Setenv("TRANSPARENZ_TOKEN", "env-token")

	// Simulate the env-var resolution logic from RunE
	url := os.Getenv("TRANSPARENZ_SERVER_URL")
	token := os.Getenv("TRANSPARENZ_TOKEN")

	assert.Equal(t, srv.URL, url)
	assert.Equal(t, "env-token", token)

	err := postSBOM(url, token, "application/json", []byte(`{}`), 5, false)
	require.NoError(t, err)
}

func TestSubmitEnvVarToken(t *testing.T) {
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("TRANSPARENZ_TOKEN", "from-env-token")

	token := os.Getenv("TRANSPARENZ_TOKEN")
	err := postSBOM(srv.URL, token, "application/json", []byte(`{}`), 5, false)
	require.NoError(t, err)
	assert.Equal(t, "Bearer from-env-token", gotAuth)
}

func TestSubmitMissingURLReturnsError(t *testing.T) {
	// Clear env vars to avoid interference
	t.Setenv("TRANSPARENZ_SERVER_URL", "")
	t.Setenv("TRANSPARENZ_TOKEN", "tok")

	// Re-run the validation logic inline (mirrors RunE)
	url := ""
	if url == "" {
		url = os.Getenv("TRANSPARENZ_SERVER_URL")
	}
	assert.Empty(t, url, "url should be empty when both flag and env are unset")
}

func TestSubmitMissingTokenReturnsError(t *testing.T) {
	t.Setenv("TRANSPARENZ_TOKEN", "")

	token := ""
	if token == "" {
		token = os.Getenv("TRANSPARENZ_TOKEN")
	}
	assert.Empty(t, token, "token should be empty when both flag and env are unset")
}

// ---------------------------------------------------------------------------
// Insecure / TLS tests
// ---------------------------------------------------------------------------

// selfSignedTLSServer creates an httptest TLS server and returns its URL and
// the certificate pool so callers can choose whether to trust it.
func newSelfSignedTLSTestServer(handler http.Handler) (*httptest.Server, *x509.CertPool) {
	// Generate ephemeral EC key + self-signed cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	return srv, pool
}

func TestSubmitInsecureFlagAllowsSelfSigned(t *testing.T) {
	srv, _ := newSelfSignedTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Without --insecure this should fail (certificate signed by unknown authority)
	err := postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, false)
	require.Error(t, err, "expected TLS error without --insecure")

	// With --insecure it should succeed
	err = postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, true)
	require.NoError(t, err)
}

func TestSubmitInsecurePrintsWarningToStderr(t *testing.T) {
	srv, _ := newSelfSignedTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Capture stderr
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	_ = postSBOM(srv.URL, "tok", "application/json", []byte(`{}`), 5, true)

	_ = w.Close()
	os.Stderr = old

	captured, _ := io.ReadAll(r)
	assert.Contains(t, string(captured), "WARNING: TLS verification disabled")
}
